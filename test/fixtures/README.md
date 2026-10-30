# Test fixtures

All transcripts here are hand-written and synthetic. They mimic the structure of real Claude Code transcripts
(split assistant lines sharing `message.id`, `tool_use` / `tool_result`, `toolUseResult`, `isSidechain`,
`subagents/`, attachment and system lines) but contain no real session data. Users are `fixture` and `alice`;
every secret-looking value is fake.

`projects/-home-fixture-proj/`:

| File | Lines | What it exercises |
|---|---|---|
| `aaaaaaaa-…-0001.jsonl` | 23 | basic turns; one response split over lines 3–6 with a duplicated uuid (line 5); `is_error` result (9); content-string and text-block results (11, 13); Stop (14) followed by system/attachment lines; `permissionMode` change (17); a rewritten line repeating tool_use `toolu_A05` (19); relative `file_path`s; a tool_use with no result (23) |
| `bbbbbbbb-…-0002.jsonl` | 6 | a Task call whose result arrives after an `isSidechain` call and result (lines 3–4) |
| `bbbbbbbb-…-0002/subagents/agent-a1b2c3.jsonl` | 4 | a subagent transcript (Pre/Post with `agentId`, an `end_turn` that must not be a Stop) |
| `cccccccc-…-0003.jsonl` | 7 + partial | malformed (2), non-object (3, 4), unknown type (5) and a partial last line without `\n` |
| `dddddddd-…-0004.jsonl` | 31 | planted secrets: one fake value per DESIGN.md §8 rule in Bash commands at lines 2, 4, …, 30 |
| `eeeeeeee-…-0005.jsonl` | 15 | Stop turns with an injected `<claims-policy>` block quoting "tests pass"; claim with evidence (5), claim without evidence (8), continuation with `stop_hook_active` (10), no claim (13), `FIXTURE_SLOW` (15) |

Hand counts (used by `cli-dryrun.test.js`): 6 files, 86 complete lines, 3 malformed, 5 sessions.
PreToolUse points: A 7, B 2, B-subagent 1, C 1, D 15, E 1 = 27 (Bash 23, Read 1, Edit 1, Write 1, Task 1).
PostToolUse points: A 5 (A02 is an error), B 2, B-subagent 1, C 1, D 15, E 1 = 25.
Stop points: A 1, B 1, E 5 = 7.

`expected/*.json` are written from each example hook's intent (see `examples/hooks/`), not from replay output.
