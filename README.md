# hook-replay

hook-replay runs a Claude Code hook against the real tool calls in your past sessions. You run it before you turn the hook on. The report shows what the hook would block, ask about, or warn on. It lists samples that can be false positives. It shows the p50 and p95 latency of the hook. hook-replay is for analysis only. It does not change your sessions, your settings, or your transcripts.

Version: 0.1. Hooks reference: <https://code.claude.com/docs/en/hooks>.

## Quick start

Requirements:

- Node 20 or later.
- Linux with `bubblewrap` (`bwrap`) for isolation, installed in `/usr/bin`, `/bin`, or `/usr/local/bin` (or given with `--bwrap <path>`). The supported CPU types are aarch64 and x86_64.
- On other systems, you must use `--allow-network`. The hook then runs with no isolation at all.

Run a hook that you give on the command line:

```sh
node bin/hook-replay.js --hook 'node "$CLAUDE_PROJECT_DIR/examples/hooks/deny-rm.js"' \
  --event PreToolUse --matcher Bash --projects-dir test/fixtures/projects
```

Each hook runs in an empty temporary directory, not in your project. A relative script path does not work: if the path exists from your current directory, hook-replay stops with a usage error (exit 2). This check also looks past `NAME=value` prefixes and an `env` prefix (`FOO=1 node x.js`, `/usr/bin/env node x.js`). It does not look inside `sh -c '...'`. Use an absolute path or `$CLAUDE_PROJECT_DIR`. The variable holds the value of `--project-dir`. The default is the current directory.

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
hook-replay 0.1.0  points 59  sessions 5  isolation bwrap (read-only fs, /usr/bin/bwrap)  cwd temp  redaction on  project-dir ~/dev/hook-replay

HOOK  EVENT       MATCHER  RUNS  BLOCK  ASK  WARN  STOP  DEFER  ALLOW  ERROR  TIMEOUT  RTO  P50ms  P95ms  MAXms
h1    PreToolUse  Bash       23      3    1     0     0      0      2      0        0    0     38   44.7   48.8
latency measured at concurrency 4; sandbox: `true` took p50 9.56 ms, p95 10.95 ms wrapped; p50 1.35 ms, p95 1.89 ms unwrapped

== h1: node "$CLAUDE_PROJECT_DIR/examples/hooks/deny-rm.js"
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

The numbers in the table change from run to run. Latency depends on your machine.

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
- A temporary working directory, `<root>/work/cwd`. The temporary root has two parts: `<root>/snap` holds the transcript snapshots and is read-only for the hook; `<root>/work` (working directory, `TMPDIR`, `CLAUDE_PLUGIN_DATA`) is the only part the hook can write.
- A small environment: `PATH`, `HOME`, `USER`, `LOGNAME`, `SHELL`, `LANG`, `LC_ALL`, `LC_CTYPE`, `TZ`, the `CLAUDE_*` placeholders, `CLAUDE_HOOK_REPLAY=1`, and each name you give with `--env`.

At start, hook-replay does a probe (see "Safety and privacy" for the exact checks). If a check fails, hook-replay exits with code 3. A hook that needs a socket shows as `error` in the report.

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

The flagged outcomes are `block`, `ask`, `defer`, `warn`, and `stop`. `allow` has its own column (`ALLOW`) because it skips the permission prompt. `by_tool` in `--json` lists only the tools that the hook ran on.

A candidate false positive is a flagged call that the real session ran, and the call succeeded. This is evidence. It is not a verdict. The real call could have been a mistake. You decide. Each sample shows what the real session did: `ran and succeeded`, `ran and failed`, or no result. For a Stop hook, the candidate false positive is a flagged turn after which the real session stopped and waited for the user (`flagged_real_user_prompt` in `--json`).

Samples are chosen by hash of the call and the hook. The same input gives the same samples. Use `--samples <n>` to change the count.

Two cases need care:

- A PostToolUse `block` is feedback to Claude. The tool already ran. The sample says `effect: feedback to Claude; the tool already ran`.
- A Stop `additionalContext` keeps Claude working. hook-replay counts it as `block`, not `warn`.

Latency is measured from process start to process end. It includes the wrapper. The report also shows how long `true` takes with and without the wrapper (`sandbox_overhead_ms` in `--json`: `wrapped` and `unwrapped`, each with p50 and p95). Latency depends on `--concurrency`. For clean numbers, use `--concurrency 1`. With `--writable-fs` or `--allow-network`, hook-replay always runs one hook at a time: if you give a larger `--concurrency`, it prints a note, adds a warning to the report, and records 1 as `config.concurrency`.

Use `--fail-on block,ask` to get exit code 4 when any of these outcomes occurred.

## Safety and privacy

CAUTION: Replay EXECUTES the hook once for each matching call. A hook with side effects repeats them N times. Run `--dry-run` first to see N.

- By default, the hook can write only in `<root>/work` (its working directory, `TMPDIR` and `CLAUDE_PLUGIN_DATA`), and in FIFOs (see the residual risks). The rest of the file system is read-only for the hook. This includes `<root>/snap`, where the transcript snapshots are: hook-replay opens those files outside the sandbox, so in the sandbox the hook cannot create, link, or replace entries there. hook-replay opens `<root>/snap` once, at start. It creates, checks, and removes each snapshot through that open directory (`/proc/self/fd/<n>/<name>`), with `O_EXCL|O_NOFOLLOW`, so a link at any part of the path cannot send the file to a different directory. Before each create, and before and after each hook run, it checks that the paths `<root>/snap` and `<root>` still name the directories that it made. If one does not, hook-replay stops with an error and exit code 1, and prints no report. The hook gets its own `/dev` (no access to your terminals in `/dev/pts`, its own `/dev/shm`), an empty `/tmp`, and an empty `/run/user/<uid>` (no D-Bus or other session sockets). A hook script under `/tmp` is made visible, read-only.
- `--writable-fs` lets the hook write anywhere that you can write, N times, except `<root>/snap`, which stays read-only. This includes files such as `~/.claude/settings.json` or `~/.bashrc` that run later outside the sandbox. hook-replay prints a warning. The hook still gets its own `/dev` and an empty `/run/user/<uid>`. `<root>` is bound read-only onto itself, so the hook cannot rename it. The hook can rename a directory above `<root>` that you can write (your `TMPDIR`, for example) and make new directories at the old paths. Then hook-replay stops, at the latest when that hook run ends, with the error above. A rename that is undone before the next check is not seen. In this mode, hooks run one at a time (`--concurrency` is 1), so such a rename can change the result of only the hook run that did it.
- `--allow-network` runs the hook without the sandbox. Nothing can stop the hook then: it can write, rename, or replace `<root>/snap` and `<root>`, as it can any of your files, and it can read the snapshots. hook-replay does not open an entry that the hook puts at a snapshot name: it uses a new name and adds a warning to the report. A run whose snapshot the hook changed gets the fidelity flag `snapshot_tampered`. If the hook renames or replaces `<root>/snap`, `<root>`, or a directory above them, hook-replay stops at the next check (before or after a hook run, or before a snapshot create) with the error above. Hooks run one at a time in this mode too, so a change that is undone before the run ends can change the result of only that run. At exit, hook-replay removes only what it created: the snapshots through the open directory, and `<root>` by its path only while that path still names the `<root>` that hook-replay made. Otherwise it removes `<root>/snap` and `<root>/work` through an open descriptor of `<root>`, and then `<root>` under its new name if it is empty.
- `--readonly-fs` is deprecated. It has no effect, because read-only is the default.
- The sandbox needs `bwrap`. hook-replay does not look for it on `PATH`. It uses the first of `/usr/bin/bwrap`, `/bin/bwrap`, and `/usr/local/bin/bwrap` (after symbolic links) that is a regular file owned by root and not writable by group or others, in a directory with the same two properties. `--bwrap <path>` uses a different binary, with no such check. The report header and `isolation.bwrap` in `--json` show which binary ran and where it came from. No probe can detect a malicious wrapper: a binary that prints the answers that the probe expects and then runs the hook without isolation passes every check. Give `--bwrap` only a binary that you trust.
- At start, a probe runs these checks with the exact wrapper and seccomp filter. If one fails, hook-replay stops with exit code 3.
  1. The wrapper exits 0 for `true`.
  2. Inside the sandbox, each of these fails with `EACCES`: connect to a Unix socket in `<root>/work`; TCP connect to `127.0.0.1`, to `::1`, to the first non-loopback IPv4 address, and to the first global or ULA IPv6 address of the host (each if the host has it); open an `AF_NETLINK` socket. If `python3` is on `PATH`, also `AF_PACKET`, raw IPv4, and raw IPv6 sockets. hook-replay finds `python3` on `PATH`, so a different `python3` earlier on `PATH` can give false answers to this check. The probe does not try every address family; the tests show that the filter also gives `EACCES` for `AF_VSOCK`, `AF_ALG`, and `AF_CAN`.
  3. Inside the sandbox, `/proc/self/ns/net` and `/proc/self/ns/pid` are different from those of hook-replay.
  4. Without the sandbox, the same client connects to each target that has a listener.
- Redaction is on by default. It is best-effort pattern matching. It can miss a secret. It can also hide text that is not a secret (see the path above). The kinds are: private keys (also a key cut short without its END line, and PGP private key blocks), Anthropic, OpenAI, and Stripe API keys, GitHub, GitLab, npm, and Hugging Face tokens, AWS keys, Slack tokens and Slack webhook URLs, Google keys, JWTs, `Authorization` values with any scheme (`Bearer`, `Basic`, `Digest`, ...), `Cookie` and `Set-Cookie` values, values of names such as `password`, `api_key`, `DB_PASS`, `MYSQL_PWD`, `OPENAI_KEY` (any upper-case `*_KEY`), `AccountKey` or `SharedAccessKey`, a bare `pwd=` (not `PWD=/path`), a YAML block or folded scalar (`password: |` and the indented lines below it), the whole value of a JSON key with such a name or named `auth` (a string, an array, or an object), the `value` next to a `name` or `key` that holds such a name (`{"name": "API_KEY", "value": ...}`, also in YAML), the item after `--token`, `--password`, `--pw` and similar flags (`--pw x` and `--pw=x`, also in an argv array), the password in a `.netrc` entry, the last field of a `.pgpass` line (`host:port:db:user:password`), `curl -u user:password`, `sshpass -p`, `docker login -p`, `htpasswd -b`, `aws configure set aws_secret_access_key`, the password in `auth=("user", "password")`, URL credentials and URL parameters such as `token=`, `api_key=` or `sig=` (after `?`, `&`, or `;`), hex strings after a key or header name, email addresses, home paths, your user name, and long high-entropy strings. A path is not one high-entropy string: `/` splits it. A number or `true`/`false` after such a name stays (`max_tokens: 4096`, `PASSWORD_MIN_LENGTH=8`), unless the name ends in the secret word (`PASSWORD=1234` is redacted). A `session_id` stays. A value without quotes ends before a closing quote, so `"X-Api-Key: v"` keeps its `"`. Known misses (measured by the tests or the review): a secret in prose with no name, flag, or key shape (`password hunter2`); a header name and its value in two argv items (`"Authorization", "Token x"`); a secret sent on standard input (`echo x | gh auth login --with-token`). Any string of five `:`-separated fields whose second field is a number or `*` loses its last field, also when it is not a `.pgpass` line, unless a field contains `//` (a URL, as in `app.js:12:http://localhost:3000`).
- `--show-raw` turns redaction off. The report then holds raw transcript text.
- Temporary files have mode 0600 for files and 0700 for directories. hook-replay removes them on exit and on SIGINT, SIGTERM, and SIGHUP. It cannot do this on SIGKILL: the temporary directory then stays, with raw transcript prefixes in it. Without the sandbox (`--allow-network`), the hook can copy the snapshots while it runs, and hook-replay does not remove what the hook makes outside `<root>`, for example a new directory at the old path of a `<root>` that the hook renamed.
- Nothing leaves your machine. hook-replay has no telemetry and no upload.
- The `--out` file has mode 0600.

Residual risks (DESIGN section 9):

- A hook can write data that it read into `<root>/work`, or with `--writable-fs` into any file. A process outside the sandbox can send that file later.
- The file system is read-only, but the kernel does not apply the read-only check to a FIFO (named pipe). A hook can write into any FIFO that you can write outside `/tmp`, `/dev`, and `/run/user/<uid>`, for example one under your home directory or under `/var/tmp` (both measured by the tests). A process outside the sandbox that reads such a FIFO gets what the hook writes.
- With `--allow-network`, there is no isolation. This is also the case on non-Linux systems and on other CPU types.
- CPU, memory, and process count are not limited.
- Without the sandbox (`--allow-network`), there is no pid namespace. hook-replay kills the hook's process group on a timeout and on SIGINT, SIGTERM, and SIGHUP, but a hook child that calls `setsid` leaves the group and survives.
- If someone sends SIGKILL to hook-replay, the temporary directory stays. It holds raw transcript prefixes.
- The x86_64 seccomp program was checked against hand-derived bytes only. It has not run on an x86_64 kernel. On the aarch64 test machine, the x32 and wrong-architecture rules are also checked by bytes only. The `socket()` and `io_uring_setup()` rules are checked by behaviour.

## Fidelity limits

A replay does not give the same result as a live session. Know these limits (DESIGN section 10):

1. The transcripts were recorded without your hook. A replayed `block` does not change later calls. Text that your hook would add is absent. Problems that depend on that text are under-reported.
2. Claude Code can write the transcript later than the hook runs. The real hook can see less than the snapshot holds.
3. Some values are approximations: the output schema, `stop_hook_active`, `permission_mode`, and `tool_response` when a line has no `toolUseResult`.
4. Not reproduced: the `if` field (use `--ignore-if` to run those hooks anyway), parallel hooks, and the limit on Stop continuations.
5. Absent fields: `prompt_id`, `effort`, `mcp_server`, `duration_ms`, `agent_type`, `scratchpad_dir`.
6. A hook that looks for files next to the transcript does not find them.
7. The environment, the temporary working directory, the missing sockets, and the read-only file system differ from a live session. `--cwd recorded` uses the recorded directory when it exists.
8. A stateful hook sees thousands of calls in minutes.
9. v0.1 handles only `command` hooks for PreToolUse, PostToolUse, and Stop. It skips `async` hooks and shows each skip as a warning.
10. Windows and macOS isolation are not available.

The classification rules are not yet compared with a real Claude Code run (ADR-0001).

## Dogfood: staff-kit hooks

The owner ran the two hooks from
[claude-staff-kit](https://github.com/rajib2k5/claude-staff-kit) against their own local transcripts on
2026-10-30. The transcripts stay on that machine. This section gives only counts and categories. It gives no
command text.

The corpus had about 1,190 transcript files from 44 sessions (subagent files included).

**`evolv-destructive-guard.js` (PreToolUse, all tools)**

| Runs | pass | ask | block | error | timeout | p50 | p95 | max |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 67,673 | 67,448 | 218 | 7 | 0 | 0 | 50.9 ms | 132 ms | 352 ms |

- 215 of the 218 asks and all 7 blocks were on `Bash`. The other asks were 1 on `Write` and 2 on `Edit`.
- In 219 of the 225 flagged calls, the real session ran the call and it succeeded. Each of these is a candidate
  false positive.
- The 5 sampled blocks were not destructive. They matched on text in the command:
  - An install script that `curl` downloaded matched "filesystem format / raw device write".
  - Text in a `printf` matched "terraform destroy".
  - Deletes inside Claude's own `/tmp/claude-*` scratchpad matched "delete of /tmp (the filesystem root)",
    although the guard's own rules exempt that scratchpad.
- That full run used the old writable-filesystem default, with 4 hooks in parallel on a machine that was also
  running test suites. A second run, on a 10% sample (`--sample 0.1`) with the current read-only default, gave
  6,842 runs: 24 ask, 1 block, 0 errors, p50 42 ms, p95 64 ms. All latencies include the sandbox. The
  sandbox added about 10 ms per run at p50 (wrapped `true` 13.6 ms, unwrapped 4.2 ms).

**`evolv-skills-enforcer.js` (Stop)**

| Runs | pass | block | p50 | p95 | max |
|---:|---:|---:|---:|---:|---:|
| 1,912 | 1,822 | 90 | 41 ms | 59 ms | 107 ms |

- All 90 flags are `additionalContext`. On Stop, that keeps Claude working, so hook-replay counts them as
  `block`. After 36 of the 90, the real session stopped and waited for the user.
- The sampled flags were turns that gave a claim and its evidence in the same message (for example a test
  count). The hook's evidence pattern did not match that text.
- **The motivating bug:** we also replayed a copy of the hook with its `stripOwnBlocks` fix removed. That copy
  flagged 90 of 1,897 Stop points. The fixed hook flagged 90 of 1,896 in the same run.
  Only 6 of the transcripts contain the hook's injected policy block. This shows a known limit of replay (see Fidelity limits): if a session was recorded
  without the hook, the hook's own injected text is not in it.

## Development

Run the tests:

```sh
npm test
```

This runs `node --test`. The last run printed 381 tests, 381 pass, 0 fail. The sandbox tests skip when `bwrap` is not installed.

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
