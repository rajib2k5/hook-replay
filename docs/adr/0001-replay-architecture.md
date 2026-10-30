# ADR-0001: Replay hooks with our own subprocess runner over exact transcript prefixes, in a network namespace

Status: Proposed
Date: 2026-10-29
Deciders: project owner (scope, runtime, isolation tooling); design author (runner, classification, snapshots)

Proposed, not Accepted: the classification rules in DESIGN.md §6 have not yet been compared against a real Claude
Code run on the fixture hooks (DESIGN.md §13).

## Context

hook-replay answers one question before a user enables a Claude Code hook: on my real past tool calls, how
often would it block, ask or warn, on what, and how slow is it? The forces:

- **Corpus.** About 2 GB in about 1,100 JSONL transcripts, 0.1–6.6 MB each, some single lines several MB. It is
  private, so it is read-only, never shipped, and redacted in output.
- **Hooks are arbitrary programs.** Shell scripts, Node, Python, exec form or `sh -c` shell form. Their
  contract with Claude Code is stdin JSON in, then exit code, stdout and stderr out, with a documented precedence
  table (exit 2 blocks even over JSON `allow`; other non-zero exits with valid JSON are decided by the JSON;
  `continue:false` wins over event fields).
- **Hooks read more than stdin.** The dogfood Stop hook `evolv-skills-enforcer.js` reads the last 60 KB of
  `transcript_path`. Its own comment records 39 false warnings on one real transcript, because the tail held the
  policy text the hook had injected. A replay that hands such a hook the whole final transcript would make the
  hook see turns that came after the point being replayed.
- **Volume × side effects.** One replay runs the hook thousands of times. Anything the hook does (writing a
  log, calling an API, starting a daemon) happens thousands of times.
- **Measured on this machine** (N=50, sequential, p50): `sh -c true` 1.1 ms; under
  `unshare --user --net --pid --fork --kill-child --map-current-user` 1.7 ms; under bwrap 4.9 ms; `node -e 0`
  20.5 ms. Both wrappers are unprivileged and leave only `lo` in `/proc/net/dev`. Without a pid namespace, a
  hook's `setsid sleep &` survived SIGKILL of the wrapper; with one, it died.
- **Owner's fixed choices.** Node ≥ 20, zero dependencies, `unshare` then `bwrap` for network isolation,
  `sh -c` semantics, and analysis only.

## Decision

1. We will run each hook as **a separate subprocess per payload**, in the form Claude Code uses (shell form
   `sh -c`, or exec form when `args` is set). Each run gets stdin JSON, a scrubbed environment and a timeout,
   and is wrapped in a user + network + pid namespace (`unshare`, else `bwrap`). One probe at startup checks
   that the wrapper isolates the network. If no wrapper passes it, we refuse to run unless the user gives
   `--allow-network`.
2. We will **classify outcomes with our own pure function**, taken from the documented exit-code × stdout
   table and the per-event decision fields. Where the docs are silent (the exact output schema), we mark the
   rule as our approximation.
3. We will give every payload a **`transcript_path` that is an exact byte prefix** of the source transcript,
   ending at that payload's point. We build one growing temp file per transcript and run that transcript's
   payloads in order (append, or truncate when a point is released late). Different transcripts run in
   parallel (default 4). We keep the prefix exactly as recorded, including earlier hook output lines.
4. We will **report per hook**, with candidate false positives and a "did the real session go ahead" signal,
   not a verdict. No ground truth is claimed.

## Alternatives considered

### A. Import JavaScript hooks in-process (`import()` / `require()` and call their logic)

About 20 ms faster per payload: no process start, since `node -e 0` costs 20.5 ms. 100k payloads would take
seconds, not about 9 minutes. **Rejected** for these reasons:
- It only works for JS hooks that export their logic. Shell, Python and most third-party hooks are excluded,
  and the destructive guard exports `decide()` but not its output-building `main()`.
- It does not exercise the contract that we are claiming to predict: stdin parsing, `process.exit` codes,
  stdout framing, and the exit-2 and invalid-JSON paths.
- A hook's `process.exit()` would kill the replay. Module state leaks between payloads. No network or pid
  isolation is possible inside our own process.
- The latency it reports leaves out process start, which is a real part of what the user pays per tool call.

**Would win if:** the per-payload spawn cost became the bottleneck, for example ≥ 10M payloads. Then an opt-in
`--in-process` mode for hooks that export a known function could exist beside the subprocess mode, never
replace it.

### B. Replay through real Claude Code (headless `claude -p` / Agent SDK with the hook configured)

This gives the highest classification fidelity, because Claude Code's own parser and precedence rules decide.
It also removes our approximation of the output schema. **Rejected** for these reasons:
- Claude Code fires PreToolUse only for a tool call that the model makes in a live turn. We cannot inject
  historical tool calls without the model producing them again. That costs tokens (money) per payload, needs
  network, and is non-deterministic.
- If the hook allows the call, Claude Code then **executes the tool**: the historical `rm -rf`, `git push`, or
  MCP call would run again. This breaks the analysis-only constraint, and no sandbox makes it acceptable.
- It needs an authenticated install and is far slower: seconds per payload, not milliseconds.

**Would win if:** Claude Code shipped a supported "evaluate hooks on this payload, do not execute" entry point,
or exported its hook-output parser as a library. Then we would call that instead of `classify()` and keep
everything else. That is the main revisit trigger below.

### C. Pass the original transcript path, or copy a full prefix per point

These are snapshot alternatives inside the chosen architecture.
- **Original path** costs nothing, but the hook sees the future: every later turn, and the hook outputs
  recorded after the point. For a tail-reading Stop hook this replays the 39-false-warning defect in a new form.
  **Rejected** because it is wrong.
- **A fresh full copy per point** is correct and simple, but costs O(points × transcript size) of writes. For a
  6.6 MB transcript with hundreds of points, that is GBs per file. **Rejected** on cost.
- **An incremental prefix per transcript** (chosen) writes each corpus byte at most about once. Peak disk is
  about concurrency × the largest transcript, about 26 MB here. It forces one-at-a-time execution within a
  transcript.

**Would win if:** hooks never read `transcript_path`. We cannot know that for arbitrary hooks.

### (Considered and dismissed) Static analysis of the hook source

This cannot generalise across languages, and it says nothing about latency.

## Consequences

**Positive.**
- Any language and both command forms work, with the same exit-code and stdout contract Claude Code applies.
- Latency includes process start, the number a user actually pays.
- The network isolation is verified at startup, not assumed.
- A daemonising or hanging hook is fully torn down at timeout.
- The output is deterministic for deterministic hooks: results are sorted by `(file, line, hook)`, whatever
  the concurrency.

**Negative.**
- We own a re-implementation of Claude Code's outcome rules. It can drift when Claude Code changes, and its
  output-schema check is our approximation. The golden fixtures catch our regressions, not upstream changes.
- About 20 ms per payload for Node hooks. Within a transcript, runs are serialised by the snapshot design.
- A pid namespace changes signal semantics. bwrap reports death by signal as `128+N`. Under unshare the hook is
  PID 1, so a signal it sends to itself is ignored. Outcomes are unaffected, except for a hook that kills itself.
- Linux only for an isolated run. macOS needs `--allow-network` in v0.1.
- Replay is counterfactual-blind. The history was produced without this hook, so a replayed deny cannot change
  later calls, and text the hook would have injected is absent.

**Risks accepted.**
- Without `--readonly-fs`, a hook can write anywhere the user can, N times. We mitigate this with a banner,
  `--dry-run`, a temp cwd by default (this overrides the owner's "recorded cwd" default, which is still
  available as `--cwd recorded`) and `CLAUDE_HOOK_REPLAY=1`. We do not eliminate it.
- Filesystem Unix sockets stay reachable inside the network namespace.
- Raw transcript prefixes sit in a 0700 temp dir during the run, and survive if hook-replay is SIGKILLed.

## Revisit when

- Claude Code exposes a hook-evaluation entry point or parser library (then alternative B replaces
  `classify()`).
- The hooks reference changes the exit-code × stdout table or the Stop/PreToolUse decision fields (check on
  every Claude Code minor release that touches hooks; the golden tests pin our reading).
- The first comparison against a real Claude Code session disagrees with DESIGN.md §6 on any fixture (then fix
  the rules, and record the error in a new ADR).
- A corpus reaches ≥ 10M payloads, or per-run spawn cost exceeds 50% of wall time (then consider an opt-in A).
- macOS users are a meaningful share of issues (then add a `sandbox-exec` wrapper).
