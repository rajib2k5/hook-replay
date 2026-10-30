# hook-replay

hook-replay runs a Claude Code hook against the real tool calls in your past sessions. You run it before you turn the hook on. The report shows what the hook would block, ask about, or warn on. It lists samples that can be false positives. It shows the p50 and p95 latency of the hook. hook-replay is for analysis only. It does not change your sessions, your settings, or your transcripts.

Version: 0.1. Hooks reference: <https://code.claude.com/docs/en/hooks>.

## Quick start

Requirements:

- Node 20 or later.
- Linux with `bubblewrap` (`bwrap`) for isolation. The supported CPU types are aarch64 and x86_64.
- On other systems, you must use `--allow-network`. The hook then runs with no isolation at all.

Run a hook that you give on the command line:

```sh
node bin/hook-replay.js --hook 'node "$CLAUDE_PROJECT_DIR/examples/hooks/deny-rm.js"' \
  --event PreToolUse --matcher Bash --projects-dir test/fixtures/projects
```

Each hook runs in an empty temporary directory, not in your project. A relative script path does not work. Use an absolute path or `$CLAUDE_PROJECT_DIR`. The variable holds the value of `--project-dir`. The default is the current directory.

Other ways to run:

- `--settings <file>` runs every command hook in a `settings.json` or a plugin `hooks.json`.
- `--dry-run` counts the calls that would run. It runs nothing.
- `--json` prints the report as JSON (`hook-replay/report@1`). `--out <file>` also writes it to a file with mode 0600.
- `--help` lists all options.

Without `--projects-dir`, hook-replay reads `~/.claude/projects`.

Dry run on the fixtures:

```text
hook-replay 0.1.0: dry run, nothing executed
files 6  lines 86  sessions 5
HOOK EVENT TOOL POINTS
h1 PostToolUse Edit 1
h1 PostToolUse Write 1
```

Real output for the command above (the four warning lines are cut):

```text
hook-replay 0.1.0  points 59  sessions 5  isolation bwrap  cwd temp  redaction on  project-dir ~/dev/hook-replay

HOOK  EVENT       MATCHER  RUNS  BLOCK  ASK  WARN  STOP  DEFER  ERROR  TIMEOUT  RTO  P50ms  P95ms  MAXms
h1    PreToolUse  Bash       23      3    1     0     0      0      0        0    0  110.2  143.9  160.3
latency measured at concurrency 4; sandbox overhead p50 27.11 ms, p95 42.14 ms

== h1: node "$[REDACTED:high_entropy].js"
top tools by flagged count: Bash 4
flagged and the real call succeeded: 3
  [1fb6f8a4d028] block/permission_decision Bash -home-fixture-proj/cccccccc-0000-4000-8000-000000000003.jsonl:6 2026-10-03T08:00:01.000Z exit 0 112.9 ms
      input:  {"command":"rm -rf node_modules"}
      reason: rm -rf is not allowed
      real session: the real session ran this call and it succeeded; if that was fine, this flag is a candidate false positive
  [24c8fb10a87d] ask/permission_decision Bash -home-fixture-proj/aaaaaaaa-0000-4000-8000-000000000001.jsonl:8 2026-10-01T10:00:04.000Z exit 0 86.1 ms
      input:  {"command":"git push --force origin main"}
      reason: force push needs confirmation
      real session: the real session ran this call and it failed
```

The redactor replaced the hook path in the command line. A long path looks like a secret to the redactor (see "Safety and privacy"). The numbers in the table change from run to run. Latency depends on your machine.

## How it works

hook-replay reads the transcripts, builds one hook payload for each tool call, runs the hook with that payload on stdin, and classifies the result. Each part has its own module in `src/`. The design is in `docs/DESIGN.md`. The decision record is `docs/adr/0001-replay-architecture.md`.

### Payload reconstruction

| Event | Where the payload comes from |
|---|---|
| PreToolUse | Each `tool_use` block in an assistant line. Relative `file_path` values become absolute. |
| PostToolUse | Each `tool_result` block that matches an earlier `tool_use` and has no error. `tool_response` comes from `toolUseResult`, or else from the block content. |
| Stop | Each assistant line with `stop_reason` `end_turn` in a main transcript. `last_assistant_message` is the joined text of the message. |

A result with `is_error` fires PostToolUseFailure in Claude Code. v0.1 does not replay that event and counts these results as skipped.

Subagent transcripts give Pre and Post payloads with an `agent_id`. They never give a Stop payload. `--no-subagents` leaves them out.

hook-replay does not invent fields. Fields that the transcript does not hold, such as `prompt_id`, `effort`, and `duration_ms`, are absent.

`transcript_path` points to a snapshot. The snapshot is an exact byte prefix of the real transcript. It ends at the point being replayed. A hook that reads the end of the transcript sees what it could have seen at that point, not the later turns.

### Sandbox

Each run goes through `bwrap` with these settings:

- New user, network, pid, ipc, uts, and cgroup namespaces (`--unshare-all`).
- A seccomp filter. `socket()` fails with `EACCES` for every address family. This also closes Unix sockets such as docker and D-Bus. `io_uring_setup()` fails with `ENOSYS`.
- `--new-session` and `--die-with-parent`.
- A temporary working directory.
- A small environment: `PATH`, `HOME`, `USER`, `LOGNAME`, `SHELL`, `LANG`, `LC_ALL`, `LC_CTYPE`, `TZ`, the `CLAUDE_*` placeholders, `CLAUDE_HOOK_REPLAY=1`, and each name you give with `--env`.

At start, hook-replay does a probe. The probe tries to connect out of the sandbox with a Unix socket and with TCP. If any attempt works, hook-replay exits with code 3. A hook that needs a socket shows as `error` in the report.

### Classification

hook-replay applies the exit-code and JSON rules from the hooks reference. The first matching rule wins.

| What the hook did | Outcome | What Claude Code does |
|---|---|---|
| Exit 2 (PreToolUse) | `block` | The tool call does not run. Claude gets stderr. |
| `permissionDecision: "deny"` | `block` | The tool call does not run. |
| `permissionDecision: "ask"` | `ask` | Claude Code asks you. |
| `permissionDecision: "defer"` | `defer` | Claude Code postpones the decision. |
| `permissionDecision: "allow"` | `allow` | The permission prompt is skipped. |
| Exit 2 or `decision: "block"` (PostToolUse) | `block` | The tool already ran. Claude gets the message as feedback. |
| Exit 2, `decision: "block"`, or `additionalContext` (Stop) | `block` | Claude keeps working. |
| `continue: false` | `stop` | Claude stops. |
| `additionalContext` or `systemMessage` with no decision | `warn` | Claude gets extra text. |
| Exit 0 and no decision | `pass` | The normal permission flow continues. |
| Bad JSON, bad exit code, or spawn failure | `error` | Depends on `onFailure`. |
| The hook's own timeout | `timeout` | Claude Code stops the hook. |
| The `--timeout` cap of hook-replay | `replay_timeout` (RTO) | The real result is unknown. |

The hooks reference does not publish the full output schema. The check in hook-replay is an approximation. If a hook has `onFailure: "block"`, a failed run counts as `block`.

## Reading the report

The flagged outcomes are `block`, `ask`, `defer`, `warn`, and `stop`. `allow` has its own column in `--json` because it skips the permission prompt.

A candidate false positive is a flagged call that the real session ran, and the call succeeded. This is evidence. It is not a verdict. The real call could have been a mistake. You decide. Each sample shows what the real session did: `ran and succeeded`, `ran and failed`, or no result.

Samples are chosen by hash of the call and the hook. The same input gives the same samples. Use `--samples <n>` to change the count.

Two cases need care:

- A PostToolUse `block` is feedback to Claude. The tool already ran. The sample says `effect: feedback to Claude; the tool already ran`.
- A Stop `additionalContext` keeps Claude working. hook-replay counts it as `block`, not `warn`.

Latency is measured from process start to process end. It includes the wrapper. The report also shows the cost of the wrapper (`sandbox overhead`). Latency depends on `--concurrency`. For clean numbers, use `--concurrency 1`.

Use `--fail-on block,ask` to get exit code 4 when any of these outcomes occurred.

## Safety and privacy

CAUTION: Replay EXECUTES the hook once for each matching call. A hook with side effects repeats them N times. Run `--dry-run` first to see N.

- `--readonly-fs` makes the file system read-only for the hook, except the temporary directory. It needs `bwrap`. You cannot use it with `--allow-network`.
- Without `--readonly-fs`, the hook can write anywhere that you can write.
- Redaction is on by default. It is best-effort pattern matching. It can miss a secret. It can also hide text that is not a secret (see the path above). The kinds are: private keys, API keys, GitHub, GitLab, npm, and Hugging Face tokens, AWS keys, Slack tokens, Google keys, JWTs, `Authorization` and `Bearer` values, values of names such as `password` or `api_key`, URL credentials, email addresses, home paths, your user name, and long high-entropy strings.
- `--show-raw` turns redaction off. The report then holds raw transcript text.
- Temporary files have mode 0600 for files and 0700 for directories. hook-replay removes them on exit and on SIGINT, SIGTERM, and SIGHUP.
- Nothing leaves your machine. hook-replay has no telemetry and no upload.
- The `--out` file has mode 0600.

Residual risks (DESIGN section 9):

- A hook can write data that it read into a file. A process outside the sandbox can send that file later.
- With `--allow-network`, there is no isolation. This is also the case on non-Linux systems and on other CPU types.
- CPU, memory, and process count are not limited.
- Without the sandbox, a hook child that calls `setsid` can survive a timeout.
- If someone sends SIGKILL to hook-replay, the temporary directory stays. It holds raw transcript prefixes.
- The x86_64 seccomp program was checked against hand-derived bytes only. It has not run on an x86_64 kernel.

## Fidelity limits

A replay does not give the same result as a live session. Know these limits (DESIGN section 10):

1. The transcripts were recorded without your hook. A replayed `block` does not change later calls. Text that your hook would add is absent. Problems that depend on that text are under-reported.
2. Claude Code can write the transcript later than the hook runs. The real hook can see less than the snapshot holds.
3. Some values are approximations: the output schema, `stop_hook_active`, `permission_mode`, and `tool_response` when a line has no `toolUseResult`.
4. Not reproduced: the `if` field (use `--ignore-if` to run those hooks anyway), parallel hooks, and the limit on Stop continuations.
5. Absent fields: `prompt_id`, `effort`, `mcp_server`, `duration_ms`, `agent_type`, `scratchpad_dir`.
6. A hook that looks for files next to the transcript does not find them.
7. The environment, the temporary working directory, and the missing sockets differ from a live session. `--cwd recorded` uses the recorded directory when it exists.
8. A stateful hook sees thousands of calls in minutes.
9. v0.1 handles only `command` hooks for PreToolUse, PostToolUse, and Stop. It skips `async` hooks and shows each skip as a warning.
10. Windows and macOS isolation are not available.

The classification rules are not yet compared with a real Claude Code run (ADR-0001).

## Dogfood: staff-kit hooks

<!-- DOGFOOD-RESULTS -->

## Development

Run the tests:

```sh
npm test
```

This runs `node --test`. The last run printed 240 tests, 240 pass, 0 fail. The sandbox tests skip when `bwrap` is not installed.

The fixtures are in `test/fixtures/`:

- `projects/-home-fixture-proj/` holds six synthetic transcripts.
- `expected/*.json` holds the expected outcome of each example hook. The expected files are written from the intent of each hook, not from the output of hook-replay.
- `README.md` lists what each transcript tests and the hand counts.
- `examples/hooks/` holds the three example hooks.

To add a fixture:

1. Write a transcript by hand in `test/fixtures/projects/-home-fixture-proj/`. Use the user name `fixture` or `alice`. Use only fake values.
2. Count the new lines and points by hand. Update the table and the counts in `test/fixtures/README.md` and in `test/cli-dryrun.test.js`.
3. Write the expected outcomes in `test/fixtures/expected/` from the intent of the hook.
4. Run `npm test`.

The fixtures are synthetic. Never commit a real transcript. Real transcripts hold private data.

## License

MIT. See `LICENSE`.
