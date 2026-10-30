# hook-replay

Run a Claude Code hook against your past sessions before you turn it on.

Work in progress.

## Reading the outcomes

`block` on a **PreToolUse** hook means the tool call would not have run. `block` on a **PostToolUse** hook
(mechanism `exit2_feedback` or `decision_block_feedback`) cannot undo anything: the tool already ran, and Claude
only gets the hook's message as feedback. Its samples say `effect: feedback to Claude; the tool already ran`.
`block` on a **Stop** hook means Claude would have been sent back to keep working.

For exit code 2 the reason shown is the hook's stderr, unless the hook also printed JSON that itself blocks
(`permissionDecision: "deny"` or `decision: "block"`); then it is that JSON's reason.
