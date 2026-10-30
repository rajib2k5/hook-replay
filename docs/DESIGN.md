# hook-replay v0.1 — design

Status: Proposed · Date: 2026-10-29 · Decision record: [ADR-0001](adr/0001-replay-architecture.md)

Before you turn on a Claude Code hook, run it against your past sessions' real tool calls. The report gives what
it would block/ask/warn on, redacted candidate false positives, and p50/p95/max latency. Analysis only.

Rules cite the hooks reference (code.claude.com/docs/en/hooks, 2026-10-29) as [docs: <section>]; **(our choice)**
marks where the docs are silent (gaps in §10).

## 1. Problem, constraints, non-goals

**Constraints.** Node ≥ 20, ESM, zero runtime deps, `node:test`. Corpus `~/.claude/projects/**/*.jsonl`: ≈ 2 GB,
≈ 1,100 files of 0.1–6.6 MB, single lines of several MB. It is private: read-only, copied only into a 0700 temp
dir, nothing raw on stdout without `--show-raw`. The hook is user code we execute thousands of times.

**Non-goals (v0.1).** Events other than PreToolUse, PostToolUse, Stop (no PostToolUseFailure, SubagentStop,
UserPromptSubmit, SessionStart). Hook types other than `command` (no http, mcp_tool, prompt, agent). `async`
and `asyncRewake` hooks. Evaluating the `if` field. Combining several hooks into one verdict per call (we report
per hook). Simulating the consequences of a verdict (a replayed deny does not change later calls). Labelled
ground truth. Windows. macOS network isolation. Re-running tools. Any upload or telemetry.

## 2. Architecture (the seam)

`corpus → lines → reconstruct → PayloadPoint → (matcher × HookSpec) → snapshot + sandbox + runner → classify →
redact → report`, one module each under `src/`, CLI in `bin/hook-replay.js` (`node:util` `parseArgs`). The seam is
the `PayloadPoint`: reconstruction knows nothing about hooks; the runner and classifier know nothing about
transcripts. `classify`, `matches`, `redact`, `reconstruct` (over an in-memory line list) and the percentile
function are pure and carry most unit tests.

```ts
type PayloadPoint = { key: string /* `${relPath}:${lineNo}:${event}:${toolUseId??''}`, stable */;
  event: 'PreToolUse'|'PostToolUse'|'Stop'; file: string; lineNo: number; timestamp: string|null;
  snapshotEnd: number /* snapshot = source bytes [0, snapshotEnd) */; payload: object /* minus transcript_path */;
  realSignal: 'ok'|'error'|'none'|'user_prompt'|'assistant_continued'|'eof'; fidelity: string[] };
type HookSpec = { id: string; key: string; event; matcher?: string; command: string; args?: string[];
  timeoutS: number /* default 600 [docs: Common fields] */; onFailure: 'continue'|'block'; source: string };
type RunResult = { exitCode: number|null; signal: string|null; stdout: string; stderr: string;
  stdoutTruncated: boolean; timedOut: boolean; timeoutSource: 'hook'|'replay_cap'|null;
  spawnError: string|null; latencyMs: number };
type Verdict = { outcome: Outcome; mechanism: string; reason: string|null };
```

## 3. Corpus reading and payload reconstruction

**Discovery.** Walk `--projects-dir` (default `~/.claude/projects`) for `*.jsonl`, no symlinks, sorted bytewise.
Main = `<proj>/<uuid>.jsonl`; subagent = under `<proj>/<uuid>/subagents/**`. Size at open is EOF (live files grow).
A file that cannot be opened is counted as `corpus.files_unreadable`, named in a report warning by count only, and
skipped; the run goes on.

**Lines.** `lines.js` splits a byte stream on `\n` (not `readline`), yielding `{offset, length, lineNo, bytes}`.
Over `--max-line-bytes` (default 16 MiB): `bytes: null`, counted `lines_oversize`, still in the byte prefix. A last
line without `\n` is ignored (partial write). Parse failure or non-object → `lines_malformed`; unknown `type` → skip.

**Session state** (per file): `permissionMode` (last `permissionMode` seen on any line, default `"default"`; a
value outside `default plan acceptEdits auto dontAsk bypassPermissions` is emitted as `"default"` with fidelity
`permission_mode_unknown`); `lastCwd` (last `cwd` seen on any line);
`pending: Map<tool_use_id,{name,input,lineNo}>`; `seenUuids`, `seenToolUseIds` (dedupe of rewritten lines, first
wins); `msgText: Map<message.id,string[]>`; last Stop index and whether a real user prompt followed it.

**Common fields:** `session_id` (envelope `sessionId`, else the uuid in the path), `transcript_path` (snapshot,
§5), `cwd` (envelope, else the last `cwd` seen in the file, else omitted with fidelity `cwd_missing`; see
Deviations), `permission_mode`, `hook_event_name`, `agent_id` (envelope `agentId`, only on subagent lines: a file
under `subagents/` or a line with `isSidechain:true`). Never
invented: `prompt_id` (unless envelope `promptId`), `scratchpad_dir`, `effort`, `agent_type`, `mcp_server`, `duration_ms`.

**PreToolUse** — each `assistant` line, each content block `{type:'tool_use', id, name, input}` with `id` not yet
seen: `tool_name=name`, `tool_input=input`, `tool_use_id=id`. For `Read|Write|Edit|NotebookEdit` a relative
`file_path`/`notebook_path` is resolved against `cwd` and a leading `~` against `os.homedir()` [docs: PreToolUse
input says paths arrive absolute]. `snapshotEnd` = end of this line including `\n`. `realSignal` is filled when
the matching result arrives (`ok` / `error` if `is_error===true`), else `none` at EOF — so Pre points are emitted
only after their result or EOF. Bound: if `pending` exceeds 10,000 entries, emit the oldest with `none`.

**PostToolUse** — each `user` line, each block `{type:'tool_result', tool_use_id, is_error}` whose id is in
`pending` (a result whose id is not pending — its tool_use is in another file, comes later, or was already
answered — is counted as `corpus.orphan_tool_results`), and only if `is_error !== true` (an error fires PostToolUseFailure, out of scope; count it as
`skipped.post_tool_use_failure`). `tool_response` = top-level `toolUseResult` when it is a non-null object; else
the block's `content` if a string; else the `text` of its text blocks joined with `\n`; mark fidelity
`tool_response_from_content` in the last two cases. `snapshotEnd` = start of this line (the hook ran before
the result was written) **(our choice)**.

**Stop** — an `assistant` line with `message.stop_reason === "end_turn"` in a **main** transcript, not
`isSidechain`. `last_assistant_message` = `msgText[message.id].join('\n')` **(our choice of separator)**; an
assistant `message.content` that is a plain string counts as one text block.
`stop_hook_active` = `true` iff a previous Stop point exists in this file and no real user prompt (a `user` line
whose `message.content` is a string or only text blocks, no `isMeta`, no `tool_result`) came between them.
`background_tasks: []`, `session_crons: []`. `snapshotEnd` = end of this line. `realSignal`: what follows
before the next Stop — `user_prompt`, `assistant_continued`, or `eof`.

**Subagents** are included for Pre/PostToolUse (hooks fire inside subagents with `agent_id` [docs: Common input
fields]) and never produce Stop; `--no-subagents` excludes them. `isSidechain:true` lines count as subagent lines.

**Filters** apply before anything runs: `--project <substr>` (repeatable, matches the encoded project dir
name), `--session <uuid>`, `--since/--until` (ISO date or `Nd`, against line `timestamp`; lines without one
pass), `--sample <0..1>` (keep a point iff `sha256(key)` as a fraction < rate; deterministic, no second
pass), `--limit <n>` (default 5,000 points per hook, in deterministic order; reported as `truncated:true`).

## 4. Hook selection and matching

Exactly one of:
- `--hook "<cmd>" --event <PreToolUse|PostToolUse|Stop> [--matcher <m>] [--hook-timeout <s>] [--on-failure
  continue|block]` — shell form. `--matcher` with Stop is a usage error.
- `--settings <file>` — a settings.json or plugin hooks.json; reads `.hooks.{PreToolUse,PostToolUse,Stop}[]`
  `{matcher, hooks:[{type,command,args,timeout,onFailure,async,asyncRewake,if,shell}]}`.
  Skipped with a warning in the report: other events, `type ≠ command`, `async`/`asyncRewake`,
  `shell:"powershell"`, any `${user_config.` reference. A hook with `if` is refused unless `--ignore-if`
  (then it runs on every matcher hit and is marked `if_ignored`, i.e. counts are an upper bound).

**Matcher** [docs: Matcher patterns], applied to `tool_name`; Stop ignores it. Invalid regex = load error (exit 2).
```js
const matches = (m, name) => m === undefined || m === '' || m === '*' ? true
  : /^[A-Za-z0-9_\- ,|]+$/.test(m) ? m.split(/[|,]/).map(s => s.trim()).filter(Boolean).includes(name)
  : new RegExp(m).test(name); // unanchored
```

**Placeholders.** `CLAUDE_PROJECT_DIR` = `--project-dir` (default: hook-replay's cwd, printed in the header —
never each session's own project, which would run that project's scripts). `CLAUDE_PLUGIN_ROOT` =
`--plugin-root` (a hook referencing it without the flag is refused). `CLAUDE_PLUGIN_DATA` = `<tmp>/plugin-data`.
All three are exported as env vars; in exec form (`args` set) they are also substituted textually into
`command` and each `args` element; shell form leaves expansion to `sh` [docs: Exec form and shell form].

## 5. Execution

**Command.** Shell form: `sh -c <command>`, or `bash -c <command>` when the settings hook sets `"shell": "bash"`
(`"powershell"` and any other value are skipped with a warning; `shell` is ignored when `args` is set). Exec form:
`command` resolved on PATH, `args` as argv. Wrapped (bwrap only; `unshare` was rejected after review, see ADR-0001):
- `bwrap --dev-bind / / --proc /proc --unshare-all --new-session --die-with-parent --seccomp 3 -- <argv>`;
  with `--readonly-fs`: `bwrap --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp [--ro-bind <f> <f>]...
  --bind <tmp> <tmp> --unshare-all --new-session --die-with-parent --seccomp 3 -- <argv>`, where each `<f>` is an
  existing file under `/tmp` that the hook command names (so a hook script kept in `/tmp` still runs; files beside
  it are not visible). `--readonly-fs` with `--allow-network` is refused.
- `--unshare-all` gives new user, network, pid, ipc, uts and cgroup namespaces. `--new-session` stops a hook from
  injecting input into the terminal. The bwrap binary is resolved on PATH once, at start.
- **seccomp** (`src/seccomp.js`, classic BPF built in JS, no dependencies, handed to bwrap on a fresh pipe as fd 3
  for every run, so the hook cannot rewrite it): `socket()` fails with `EACCES` for every address family, which
  closes filesystem Unix sockets (docker, D-Bus / `systemd-run --user`, ibus, editor sockets) that a network
  namespace leaves open. `socketpair()` stays allowed (it connects nothing; Node needs it for child stdio).
  `io_uring_setup()` fails with `ENOSYS`, because `IORING_OP_SOCKET` makes a socket without `socket()`. The program
  first checks `seccomp_data.arch`; a syscall from another ABI (32-bit compat) kills the process. Supported:
  aarch64 (`AUDIT_ARCH_AARCH64` 0xC00000B7, socket 198, io_uring_setup 425) and x86_64 (`AUDIT_ARCH_X86_64`
  0xC000003E, socket 41, io_uring_setup 425, and every x32 syscall, nr ≥ 0x40000000, fails with `EACCES`). Any
  other architecture: no isolation (exit 3 unless `--allow-network`). The x86_64 program is tested only against
  hand-derived bytes; it has not run on an x86_64 kernel.

The pid namespace kills a daemonising hook with the sandbox. Measured here: `setsid sleep &` inside the hook
died at timeout. Death by signal is reported as `128+N` (bwrap is PID 1 in the namespace, so a hook's own
signals behave as normal); exit codes pass through.

**Isolation probe** (once, at start; fails closed). Under the exact wrapper and filter: (1) connect to a Unix
socket the probe listens on in its temp dir, (2) TCP connect to a listener the probe opens on `127.0.0.1` and on
the first non-loopback host address (if any); every attempt must fail and no listener may see a connection;
(3) the wrapper must exit 0 for `true` and for the probe client. Any other result (including a timeout or
unparseable output) means not isolated: exit 3 with the reason. `--allow-network` skips the probe and runs every
hook **unwrapped** (no namespaces, no seccomp); the banner, the report header and the JSON say
`network: "NOT ISOLATED"`. Non-Linux always needs `--allow-network`. Wrapper overhead (20 runs of `true`, wrapped
minus unwrapped) is reported as `sandbox_overhead_ms`.

**Process.** stdin = `JSON.stringify(payload)` then close; EPIPE on stdin is ignored. cwd = `<tmp>/cwd`
(one shared dir per run) by default; `--cwd recorded` uses the payload `cwd` if it is an existing directory,
else `<tmp>/cwd`. Environment = allowlist `PATH HOME USER LOGNAME SHELL LANG LC_ALL LC_CTYPE TZ` + `TMPDIR=<tmp>/tmp`
+ the three CLAUDE_* above + `CLAUDE_HOOK_REPLAY=1` + each `--env NAME`. `HOME` is real on purpose: hooks such
as destructive-guard decide on `os.homedir()`. Stdout and stderr captured up to 1 MiB each (excess dropped,
`stdoutTruncated`). Latency = `process.hrtime` from spawn to `close`, wrapper included.

**Timeout.** `min(hook.timeoutS, --timeout)`, `--timeout` default 10 s; `timeoutSource` = `hook` if `hook.timeoutS ≤
--timeout` else `replay_cap`. Every hook runs in its own process group; on expiry SIGKILL the group (under bwrap
this kills the namespace; unwrapped it kills children that did not leave the group, but not a `setsid` child). After exit, wait ≤ 100 ms for
pipes to close, then destroy them.

**Scheduling.** Points of one transcript run one at a time in emission order (§3), so one snapshot file per
transcript is enough. Up to `--concurrency` (default 4) transcripts run in parallel. With several hooks,
each matching hook runs once per point, sequentially, in load order. Results are sorted by `(file, lineNo,
hook id)` before reporting, so output is independent of concurrency; latency is not (use `--concurrency 1`).

**Snapshot.** Per transcript, `<tmp>/t-<n>.jsonl` (0600) inside `mkdtemp(os.tmpdir()+'/hook-replay-')` (0700).
Before a point runs: if `snapshotEnd > written`, append source bytes `[written, snapshotEnd)` read from the
source file (bytes, never re-serialised; oversize lines included); if `snapshotEnd < written` (a Pre point
released late), `ftruncate` to `snapshotEnd`. After each run, if its size ≠ `snapshotEnd` (the hook changed it),
recreate it from source. Kept as recorded, including earlier `stop_hook_summary` and hook
attachment lines, because that is what a hook at that point could have seen; lines written after the point are
not present. Delete each snapshot when its transcript finishes; remove `<tmp>` on exit. The signal handlers are
installed as soon as `<tmp>` exists (before the probe, which already spawns sandboxes): on SIGINT, SIGTERM or
SIGHUP, kill every running hook's process group, remove `<tmp>`, and exit 130, 143 or 129. SIGKILL cannot be
handled: `<tmp>` then survives (§9).
Peak disk ≈ concurrency × largest transcript (≈ 4 × 6.6 MB here).

**Dry run** reconstructs, filters, matches, prints counts per hook × tool, runs nothing. **Banner** (stderr,
always): command, number of points, isolation, cwd mode, and "replay EXECUTES this hook N times; a hook with side
effects will perform them N times".

## 6. Outcome classification

`Outcome = pass | allow | ask | defer | block | warn | stop | error | timeout | replay_timeout`.
`pass` = no decision (normal permission flow). `allow` = explicit PreToolUse allow (skips the permission prompt —
reported because it is the dangerous direction). Reported as **flagged**: `block ask defer warn stop`.

**Step 1 — parse stdout** [docs: Exit code 0]. `s = stdout.trim()`.
- `s === ''`, or `!s.startsWith('{')`, or `!s.endsWith('}')` → `PLAIN`.
- `JSON.parse(s)` gives a plain object → `JSON(o)` if `valid(o)` else `INVALID('schema')`.
- Parse fails: split `s` on `\n`, drop blank lines. If ≥ 2 lines each parse as JSON: `INVALID('multi_json')` if
  any is an object with a known field (below), else `PLAIN`. Otherwise `INVALID('parse')`.
- `stdoutTruncated` → `INVALID('stdout_over_cap')`.

`valid(o)` **(our approximation of an unpublished schema)**: known fields `continue`(boolean) `stopReason`
`systemMessage` `terminalSequence` `reason`(string) `suppressOutput`(boolean) `decision`(string, one of
`approve|block` for PreToolUse, `block` otherwise) `hookSpecificOutput`(object whose `hookEventName` equals the
event; PreToolUse `permissionDecision` ∈ `allow|deny|ask|defer`; `additionalContext` string). A known field with
the wrong type/value fails; unknown fields are ignored.

**Step 2 — decide.** First matching row wins:

| # | Condition | Outcome · mechanism |
|---|---|---|
| 1 | `timedOut`, `timeoutSource=replay_cap` | `replay_timeout` (real outcome unknown) |
| 2 | `timedOut` (hook's own timeout) | `timeout` → `fail()` |
| 3 | `spawnError` | `error` · `spawn` → `fail()` |
| 4 | exit 2, Stop, stdout empty, stderr matches `/No such file or directory/` | `error` · `exit2_missing_file` [docs: Exit code output] |
| 5 | exit 2, and `JSON(o)` with `o.continue===false` | `stop` · `continue_false` |
| 6 | exit 2 | `block` · `exit2`; reason = JSON blocking reason if any, else stderr |
| 7 | exit 0 or other, `JSON(o)` | `fields(o)`; for exit ∉ {0,2} with `onFailure=block`: `fail()` [docs: Block the action when a hook fails] |
| 8 | exit 0, `PLAIN` | `pass` |
| 9 | exit 0, `INVALID(r)` | `error` · `invalid_json:r` → `fail()` |
| 10 | other exit / signal, `PLAIN` or `INVALID` | `error` · `exit_<code>` or `signal_<name>` → `fail()` |

`fail(v)` = `block` · `on_failure_block` if `onFailure==='block'` and event ≠ Stop (Stop ignores it), else `v`.

`fields(o)` [docs: JSON output, Decision control]:
1. `o.continue === false` → `stop` (takes precedence over event-specific fields).
2. **PreToolUse**: `d = hookSpecificOutput.permissionDecision ?? {approve:'allow', block:'deny'}[o.decision]`
   (hookSpecificOutput wins if both). `deny`→`block`, `defer`→`defer`, `ask`→`ask`, `allow`→`allow`.
   Mechanism `permission_decision` or `deprecated_decision`.
3. **PostToolUse**: `o.decision==='block'` → `block` (feedback to Claude; the tool already ran).
4. **Stop**: `o.decision==='block'` → `block`; non-empty `hookSpecificOutput.additionalContext` → `block` ·
   `additional_context` — on Stop it **continues the conversation** [docs: Stop decision control], so it is not a
   warning.
5. Otherwise, non-empty `additionalContext` (Pre/Post) or `systemMessage` (any event), or Post
   `updatedToolOutput`, or Pre `updatedInput` → `warn` with that mechanism. A PreToolUse `allow`/`pass` that also
   carries `additionalContext` stays `allow`/`pass` with `annotations:['additional_context']`.
6. Else `pass`.

Dogfood consequence: `evolv-skills-enforcer.js` calls itself "advisory (never blocks)", but its Stop output is
`additionalContext`, which keeps Claude working; replay reports it as `block`.

## 7. Report

**Candidate false positives.** No ground truth exists. Per hook × flagged outcome, show the `--samples` (default
5) points with the smallest `sha256(key + hook.key)` (deterministic, spread across sessions): `sample_id` (12 hex
of that hash, stable for a later `--labels` file), session, line, timestamp, tool, redacted 300-char excerpts of
`tool_input` and reason/stderr, exit code, latency, fidelity flags, and the **real-session signal** (Pre: did
the real call run `ok`/`error`/`none`; Stop: what came next). Report wording: "the real session ran this call
and it succeeded; if that was fine, this flag is a candidate false positive" — evidence, never a verdict.
Per hook also the count `flagged ∧ real=ok`.

**Human output** (stdout, default): header (version, points, sessions, isolation, cwd mode, redaction on/off,
`--project-dir`, warnings), the table below, then per hook the top 10 tools by flagged count, error mechanisms
with counts, and samples.
```
HOOK EVENT       MATCHER RUNS  BLOCK ASK  WARN STOP DEFER ERROR TIMEOUT RTO  P50ms P95ms MAXms
h1   PreToolUse  Bash    2310      4   37    0    0     0     0       0   0     21    30   112
```

**Latency.** Over runs that exited (not timeouts). Nearest rank: sort ascending, `p(q) = xs[ceil(q·n) − 1]`;
`max`; `n`. Printed with the concurrency it was measured at and `sandbox_overhead_ms`.

**`--json`** prints one object (or `--out <file>`, written 0600). Schema id `"hook-replay/report@1"`; adding
fields keeps `@1`, removing or changing meaning bumps it. Top level: `schema, tool_version, generated_at,
redacted, isolation{network:'bwrap'|'NOT ISOLATED', readonly_fs, probe}, config{timeout_s,
concurrency, cwd_mode, project_dir, filters, sample, limit}, corpus{files, lines, lines_malformed,
lines_oversize, sessions, points_by_event}, sandbox_overhead_ms{p50,p95}, warnings[], hooks[{id, key, event,
matcher, command, source, if_ignored, runs, truncated, counts{<outcome>:n}, by_tool{<tool>:counts},
mechanisms{<mechanism>:n}, flagged_real_ok, latency_ms{n,p50,p95,max}, samples[]}]`.

**Exit codes.** 0 report produced · 1 internal failure · 2 usage/load error · 3 isolation unavailable without
`--allow-network` · 4 `--fail-on <outcome,...>` matched at least once · 130 / 143 / 129 stopped by SIGINT / SIGTERM /
SIGHUP (hooks killed, temp files removed, no report).

## 8. Redaction

On by default; `--show-raw` disables it and prints a warning line. Applied in `report.js` when a sample or
any string field is **stored** in the report model, so neither renderer can see raw text. Covers every string
from a transcript or hook output, file paths, the hook command, object keys inside `tool_input`, and the recorded
filters. **Everything else printed** goes through the same redactor: the stderr banner (hook command), settings
warnings (absolute paths), usage/load errors, the isolation error, `--dry-run` tool names (an MCP tool name can
embed anything), and internal errors, which print a one-line redacted message (the stack only with
`HOOK_REPLAY_DEBUG=1`, also redacted). Order, each replaced by `[REDACTED:<kind>]`:

1. `-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----` → `private_key`
2. `sk-ant-[A-Za-z0-9_-]{10,}`, `sk-(proj-)?[A-Za-z0-9_-]{20,}`, Stripe `[sr]k_(live|test)_[A-Za-z0-9]{10,}` → `api_key`
3. `gh[pousr]_[A-Za-z0-9]{20,}`, `github_pat_[A-Za-z0-9_]{20,}` → `github_token`; GitLab `glpat-[A-Za-z0-9_-]{20,}` →
   `gitlab_token`; npm `npm_[A-Za-z0-9]{36}` → `npm_token`; Hugging Face `hf_[A-Za-z0-9]{30,}` → `hf_token` (these
   prefixes may follow `_`, as inside a tool name, but not a letter or digit)
4. `\b(AKIA|ASIA)[A-Z0-9]{16}\b` → `aws_key`; `xox[abprs]-[A-Za-z0-9-]{10,}` → `slack_token`;
   `AIza[0-9A-Za-z_-]{35}` → `google_key`
5. `eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}` → `jwt`
6. `(Authorization:\s*|Bearer\s+)\S+` → keep the prefix, `token`
7. A name matching `[A-Z0-9_-]*(SECRET|TOKEN|PASSWORD|PASSWD|API[_-]?KEY|ACCESS[_-]KEY|PRIVATE[_-]KEY)[A-Z0-9_-]*`
   (case-insensitive; so also `X-Api-Key`, `Api-Key`, `db_password`), then an optional closing quote (`"api_key":`,
   or `\"secret\":` inside a JSON string), then `=` or `:`, then a value (`"..."`, `'...'`, `\"...\"` or `\S+`)
   → keep the name, `value`.
   7a. CLI flags with a space before the value: `--[x-]password|passwd|pass|token|secret|api-key|access-key|
   private-key[-x] <value>` (the value may not start with `-`) → `value`. `--password=X` is rule 7.
   7b. mysql/mariadb family only (`mysql`, `mysqldump`, `mariadb-dump`, ...): `-p` directly followed by ≥ 4
   non-space characters later in the same command → `-p[REDACTED:value]`. Other commands' `-p` (often a port)
   are left alone.
   7c. Hex ≥ 32 characters only in key or header context: after a name containing `key|token|secret|auth|sig|
   signature|session|cookie|credential|pass` and `=`/`:`, or after an `X-...:` header → `hex_secret`. A bare git
   SHA survives.
8. `([a-z][a-z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@` → `$1[REDACTED:userinfo]@`
9. `[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}` → `email`
10. Home paths: literal `os.homedir()`, then `/home/[^/\s]+`, `/Users/[^/\s]+`, `[A-Z]:\\Users\\[^\\\s]+`, and
    `/root` (not `/rootfs`) → `~`
11. Current username (≥ 3 chars), case-insensitive. 6+ characters: anywhere, also inside identifiers
    (`<user>_backup`, `<USER>_HOME`, `-home-<user>-`). 3–5 characters: only where no letter touches it (`emu_dir`
    and `EMU2` are redacted, `lemur` is not). → `[user]`
12. Tokens `[A-Za-z0-9+/=_-]{32,}` with Shannon entropy ≥ 4.5 bits/char → `high_entropy` (hex SHAs max 4.0)

Human output then escapes C0/C1 control characters other than `\n`/`\t` as `\xNN` (transcripts can hold terminal
escapes). Redaction is best-effort pattern matching, and the README says so.

## 9. Threat model

| Threat | Mitigation | Residual |
|---|---|---|
| Hook exfiltrates transcript data | bwrap namespaces + seccomp `socket()` → `EACCES` (no TCP/UDP, no filesystem or abstract Unix sockets, no io_uring), verified by a probe that tries to connect out; `SSH_AUTH_SOCK` is scrubbed | a hook can still write what it read into a file (see next row) for a later process to send; with `--allow-network` nothing is isolated; non-Linux and architectures other than aarch64/x86_64 have no isolation at all |
| Hook side effects × N (writes, deletes, logs) | banner, `--dry-run`, temp cwd, `CLAUDE_HOOK_REPLAY=1`, `--readonly-fs` | without `--readonly-fs` the hook can write anywhere the user can, N times (including files such as `~/.bashrc` or `~/.config/systemd/user/` that something outside the sandbox runs later). Same trust as enabling it, but N× the exposure |
| Daemonising / fork-bomb hook | pid namespace killed on timeout; process group killed unwrapped; running hooks killed on SIGINT/SIGTERM/SIGHUP | CPU, memory and process count are not limited in v0.1; unwrapped (`--allow-network`) a `setsid` child survives |
| Output bomb | 1 MiB caps | — |
| Transcript text as terminal escapes | control-char escaping | — |
| Secrets in report | §8 redaction, 0600 `--out` | pattern misses; raw prefixes sit in 0700 temp during the run and survive SIGKILL of hook-replay |
| Shipping private data | only synthetic fixtures; `package.json` `files` allowlist; test of `npm pack --dry-run` | — |
| Hook runs another project's script via `${CLAUDE_PROJECT_DIR}` | project dir is one fixed value | — |

## 10. Fidelity gaps (stated in the README and the JSON `warnings`)

1. **Counterfactual history.** The transcript was produced without this hook; a replayed deny would have changed
   every later call, but points are independent. Text a hook injects (e.g. a SessionStart policy) is absent from
   sessions recorded without it, so the 39-false-warning class of bug is under-reported there.
2. Transcript lag: the real hook may have seen less than the snapshot [docs: Common input fields].
3. Approximated: output schema (§6), `stop_hook_active`, `permission_mode`, `tool_response` without
   `toolUseResult`. Not reproduced: `if`, parallel hooks, the 8-continuation cap.
   Absent: `prompt_id`, `effort`, `mcp_server`, `duration_ms`, `agent_type`, `scratchpad_dir`.
4. `transcript_path` is a snapshot: hooks looking for files beside the transcript will not find them. Env
   allowlist, temp cwd and no sockets differ from a live session (a hook that needs the network or any socket shows as `error`).
   Stateful hooks see thousands of calls in minutes. Whether transcripts record expanded `file_path` is unknown.

## 11. Testing (test-first; `node --test`)

**Unit (pure):** `classify` — each cell of the docs' exit-code × stdout table, each §6 row, deprecated
`approve/block`, exit 2 + `continue:false`, Stop `additionalContext`, `onFailure` on Pre vs Stop, multi-line JSON,
truncated stdout, hookEventName mismatch. `matches` — every docs example (`Bash`, `Edit|Write`, `Edit, Write`,
`^Notebook`, `mcp__memory__.*`, `Edit.*` vs `NotebookEdit`, `*`, `""`). `redact` — each §8 rule; SHAs and UUIDs
survive. Percentile — n=1, n=20, ties.

**Fixture transcripts** (`test/fixtures/projects/-home-fixture-proj/…`, hand-written, user `fixture`):
basic turn; one response split across lines with a duplicated uuid; tool_use without result; `is_error`
result; permission-mode change; a subagent file and an `isSidechain` line; malformed, non-object and
unknown-type lines plus a partial last line; a planted-secrets transcript (one fake value per §8 rule, the
email `alice@example.com`, path `/home/alice/`); a Stop transcript with an injected policy block quoting
"tests pass" and a later claim-without-evidence turn. Huge lines (a 20 MiB one over the cap, a 5 MiB one under
it) are generated in a temp dir at test time, never checked in.

**Fixture hooks** (shipped in `examples/hooks/`): `deny-rm.js` (PreToolUse; `rm -rf` → deny JSON, `git push
--force` → ask, `echo` → allow, else silent); `post-generated.sh` (PostToolUse `Edit|Write`, POSIX sh + grep;
`*.generated.*` → exit 2 with stderr, `.env` → `additionalContext` JSON); `stop-claims.js` (Stop; reads the
`transcript_path` tail, strips its own policy block, `additionalContext` on a claim without evidence; sleeps
past the timeout when `last_assistant_message` contains `FIXTURE_SLOW`).

**Golden tests.** (a) Per fixture, a hand-written `expected.json` of `{key → outcome, mechanism}`, written from
the hook's intent, not from our output; replay must equal it. (b) Pipeline fidelity: a test-only hook writes
its stdin and `cat $transcript_path | sha256sum` to a file; payloads must equal hand-written expected payloads
and the snapshot hash must equal the hash of the expected byte prefix. (c) Direct run, independent of replay:
each fixture hook is spawned without hook-replay on the hand-written payload from (b) and a prefix the test cuts
from the fixture bytes at the hand-specified line count; replay's recorded exit code, stdout and outcome must
equal the direct run. A test-only hook that prints its canonical stdin and the prefix hash is run the same way,
so (c) also fails when replay's payload or prefix is wrong (the example hooks do not read `cwd`).
(d) Redaction: run the full CLI (table and `--json`) on the secrets fixture; none of the planted values, `alice`,
or `/home/` may appear; with `--show-raw` they must (proves the test can fail). (e) Isolation: a hook that
connects to a host Unix socket, to `127.0.0.1` and to a non-loopback host address fails under the wrapper with
`EACCES`, while the same command run directly connects; the probe rejects a wrapper that does not isolate or that
exits non-zero; the seccomp bytes equal hand-derived programs for aarch64 and x86_64. These tests skip, with a
printed reason, only when bwrap is not installed; with bwrap installed and isolation broken they fail. (f) Teardown: a hook that runs `setsid sleep 300 &` then hangs; after timeout
no such process remains.

**Mutation check** before calling a test done: swap rows 5 and 6, treat exit 1 + JSON as error, drop redaction
rule 9 (email), skip the `seenToolUseIds` dedupe; the suite must fail each time.

## 12. Increments

(1) `lines` + `reconstruct` + `--dry-run`, counts checked by hand on fixtures. (2) `classify`, `matcher`, `runner`
unsandboxed behind `--allow-network`; golden (a)–(c). (3) sandbox probe, wrappers, teardown; (e)–(f).
(4) `redact` + `report` (table, JSON@1, samples); (d). (5) `--settings`, placeholders, `--fail-on`, filters,
`--sample`/`--limit`. (6) Dogfood the two staff-kit hooks on the local corpus; README gets counts and p95 only.

## 13. Cost and SLI

Measured here (N=50, sequential, p50): `sh -c true` 1.1 ms, under unshare 1.7 ms, under bwrap 4.9 ms; `node -e 0`
20.5 ms plain, 16.8 ms under unshare. Re-measured after the switch to bwrap + seccomp (N=50, p50, aarch64):
`sh -c true` 1.3 ms plain, 6.2 ms wrapped; `node -e 0` 20.2 ms plain, 27.0 ms wrapped. A Node hook ≈ 20 ms/point → ≈ 200 points/s at concurrency 4 → 100k points
≈ 9 min, plus one read and one temp copy of the corpus (≈ 2 GB each). Local point count not measured (private
corpus; `--dry-run` gives it). SLI: share of runs whose outcome is caused by replay itself (`spawn`,
`stdout_over_cap`, `replay_timeout`) ≈ 0; otherwise we are measuring the replay, not the hook.
**Unverified (needs a real Claude Code or a person):** §6 agreeing with Claude Code on the fixture hooks; macOS;
whether `max_tokens` turn ends fire Stop (v0.1: no).

## Deviations (v0.1 implementation)

Smallest fixes where the text above was self-contradictory or did not work as written.

1. **§8 rule 6.** `(Authorization:\s*|Bearer\s+)\S+` leaves the token of `Authorization: Bearer <token>` unredacted:
   the first alternative consumes `Bearer` as the value, and the global match resumes after it. The rule is
   `(Authorization:\s*(?:Bearer\s+)?|Bearer\s+)\S+`. The secrets fixture plants exactly this header.
2. **§6 `fields` step 5.** "A PreToolUse `allow`/`pass` that also carries `additionalContext` stays `allow`/`pass`"
   contradicts the sentence before it (no decision + `additionalContext` → `warn`). Implemented: an explicit `allow`
   keeps `allow` with `annotations:['additional_context']`; no decision + `additionalContext` is `warn`.
3. **§7 samples for Stop.** Stop points have no `tool_input`; their sample carries a `last_assistant_message`
   excerpt in its place.
4. **§3 / §5 reading.** The banner must state N before anything runs and `--limit` needs a deterministic global
   order, so the corpus is reconstructed twice: a scan that keeps only point keys, then the run. `--sample` still
   needs no extra pass of its own.
5. **§3 `cwd`.** "cwd (envelope)" left `cwd` out of the payload whenever a line lacked it, which no live hook
   would see. Implemented: the line's `cwd`, else the last `cwd` seen in the same file (any line type), else the
   key is omitted and the point carries fidelity `cwd_missing`. Relative `file_path`s resolve against the same value.
