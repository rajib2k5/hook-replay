#!/usr/bin/env node
// Example PreToolUse hook for Bash: deny `rm -rf`, ask on `git push --force`, allow `echo`, stay silent otherwise.
// Configure with matcher "Bash". Reads the hook payload as JSON on stdin.
import fs from 'node:fs';

const payload = JSON.parse(fs.readFileSync(0, 'utf8'));
const cmd = payload.tool_name === 'Bash' && payload.tool_input && typeof payload.tool_input.command === 'string'
  ? payload.tool_input.command : '';

const decide = (permissionDecision, permissionDecisionReason) => {
  process.stdout.write(JSON.stringify({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision, permissionDecisionReason } }) + '\n');
};

if (/\brm\s+-[a-zA-Z]*r[a-zA-Z]*f|\brm\s+-[a-zA-Z]*f[a-zA-Z]*r/.test(cmd)) decide('deny', 'rm -rf is not allowed');
else if (/\bgit\s+push\b.*(--force\b|\s-f\b)/.test(cmd)) decide('ask', 'force push needs confirmation');
else if (/^\s*echo\b/.test(cmd)) decide('allow', 'echo is harmless');
