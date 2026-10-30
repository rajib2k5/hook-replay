import { test } from 'node:test';
import assert from 'node:assert/strict';
import { classify, parseStdout } from '../src/classify.js';

const run = (o = {}) => ({ exitCode: 0, signal: null, stdout: '', stderr: '', stdoutTruncated: false,
  timedOut: false, timeoutSource: null, spawnError: null, latencyMs: 1, ...o });
const c = (r, event = 'PreToolUse', onFailure = 'continue') => {
  const v = classify(run(r), { event, onFailure });
  return [v.outcome, v.mechanism];
};
const J = (o) => JSON.stringify(o);
const pre = (fields) => J({ hookSpecificOutput: { hookEventName: 'PreToolUse', ...fields } });

// Docs "Exit code output": exit code x stdout kind.
test('docs table: exit 0 x {empty, plain, valid JSON, invalid JSON}', () => {
  assert.deepEqual(c({ exitCode: 0, stdout: '' }), ['pass', 'exit0']);
  assert.deepEqual(c({ exitCode: 0, stdout: 'hello\n' }), ['pass', 'exit0']);
  assert.deepEqual(c({ exitCode: 0, stdout: J({ suppressOutput: true }) }), ['pass', 'json_no_decision']);
  assert.deepEqual(c({ exitCode: 0, stdout: '{not json}' }), ['error', 'invalid_json:parse']);
});

test('docs table: exit 2 blocks whatever stdout holds, even a JSON allow', () => {
  assert.deepEqual(c({ exitCode: 2, stdout: '' }), ['block', 'exit2']);
  assert.deepEqual(c({ exitCode: 2, stdout: 'text' }), ['block', 'exit2']);
  assert.deepEqual(c({ exitCode: 2, stdout: pre({ permissionDecision: 'allow' }) }), ['block', 'exit2']);
  assert.deepEqual(c({ exitCode: 2, stdout: '{bad}' }), ['block', 'exit2']);
});

test('docs table: other exit codes are errors unless stdout is valid JSON, whose fields decide', () => {
  assert.deepEqual(c({ exitCode: 1, stdout: '' }), ['error', 'exit_1']);
  assert.deepEqual(c({ exitCode: 1, stdout: 'oops' }), ['error', 'exit_1']);
  assert.deepEqual(c({ exitCode: 1, stdout: pre({ permissionDecision: 'deny' }) }), ['block', 'permission_decision']);
  assert.deepEqual(c({ exitCode: 3, stdout: '{bad}' }), ['error', 'exit_3']);
});

test('row 1: a replay-cap timeout is replay_timeout, even with onFailure block', () => {
  assert.deepEqual(c({ exitCode: null, signal: 'SIGKILL', timedOut: true, timeoutSource: 'replay_cap' }, 'PreToolUse', 'block'), ['replay_timeout', 'replay_cap']);
});

test('row 2: the hook\'s own timeout is timeout, and blocks with onFailure block on PreToolUse', () => {
  assert.deepEqual(c({ exitCode: null, signal: 'SIGKILL', timedOut: true, timeoutSource: 'hook' }), ['timeout', 'hook_timeout']);
  assert.deepEqual(c({ exitCode: null, signal: 'SIGKILL', timedOut: true, timeoutSource: 'hook' }, 'PreToolUse', 'block'), ['block', 'on_failure_block']);
});

test('row 3: a spawn error is error spawn', () => {
  assert.deepEqual(c({ exitCode: null, spawnError: 'ENOENT' }), ['error', 'spawn']);
});

test('row 4: Stop exit 2 with empty stdout and a missing-file stderr is a non-blocking error', () => {
  const r = { exitCode: 2, stderr: '/bin/sh: 1: /x/hook.sh: No such file or directory\n' };
  assert.deepEqual(c(r, 'Stop'), ['error', 'exit2_missing_file']);
  assert.deepEqual(c(r, 'PreToolUse'), ['block', 'exit2']);
  assert.deepEqual(c({ ...r, stdout: 'x' }, 'Stop'), ['block', 'exit2']);
});

test('row 5 before row 6: exit 2 with JSON continue:false is stop', () => {
  assert.deepEqual(c({ exitCode: 2, stdout: J({ continue: false, stopReason: 'halt' }) }), ['stop', 'continue_false']);
});

test('row 6: exit 2 reason is the JSON blocking reason if any, else stderr', () => {
  const a = classify(run({ exitCode: 2, stdout: pre({ permissionDecision: 'deny', permissionDecisionReason: 'json says no' }), stderr: 'err' }), { event: 'PreToolUse', onFailure: 'continue' });
  assert.equal(a.reason, 'json says no');
  const b = classify(run({ exitCode: 2, stderr: 'stderr says no\n' }), { event: 'PostToolUse', onFailure: 'continue' });
  assert.equal(b.reason, 'stderr says no');
});

test('row 7: exit 1 with valid JSON and onFailure block counts as a failure', () => {
  assert.deepEqual(c({ exitCode: 1, stdout: pre({ permissionDecision: 'allow' }) }, 'PreToolUse', 'block'), ['block', 'on_failure_block']);
  assert.deepEqual(c({ exitCode: 0, stdout: pre({ permissionDecision: 'allow' }) }, 'PreToolUse', 'block'), ['allow', 'permission_decision']);
});

test('row 9: exit 0 with JSON that fails the schema is error invalid_json:schema', () => {
  assert.deepEqual(c({ stdout: J({ continue: 'no' }) }), ['error', 'invalid_json:schema']);
  assert.deepEqual(c({ stdout: J({ decision: 'approve' }) }, 'Stop'), ['error', 'invalid_json:schema']);
  assert.deepEqual(c({ stdout: pre({ permissionDecision: 'maybe' }) }), ['error', 'invalid_json:schema']);
  assert.deepEqual(c({ stdout: pre({ additionalContext: 5 }) }), ['error', 'invalid_json:schema']);
});

test('row 9: hookEventName mismatch fails the schema', () => {
  assert.deepEqual(c({ stdout: J({ hookSpecificOutput: { hookEventName: 'PostToolUse', additionalContext: 'x' } }) }, 'PreToolUse'), ['error', 'invalid_json:schema']);
});

test('row 10: death by signal with plain stdout is error signal_<name>; onFailure block makes it block', () => {
  assert.deepEqual(c({ exitCode: null, signal: 'SIGSEGV' }), ['error', 'signal_SIGSEGV']);
  assert.deepEqual(c({ exitCode: 1 }, 'PostToolUse', 'block'), ['block', 'on_failure_block']);
});

test('onFailure block is ignored on Stop', () => {
  assert.deepEqual(c({ exitCode: 1 }, 'Stop', 'block'), ['error', 'exit_1']);
  assert.deepEqual(c({ exitCode: null, timedOut: true, timeoutSource: 'hook' }, 'Stop', 'block'), ['timeout', 'hook_timeout']);
});

test('fields: continue:false wins over a PreToolUse allow', () => {
  assert.deepEqual(c({ stdout: J({ continue: false, hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'allow' } }) }), ['stop', 'continue_false']);
});

test('fields: PreToolUse permissionDecision maps deny/ask/defer/allow', () => {
  assert.deepEqual(c({ stdout: pre({ permissionDecision: 'deny' }) }), ['block', 'permission_decision']);
  assert.deepEqual(c({ stdout: pre({ permissionDecision: 'ask' }) }), ['ask', 'permission_decision']);
  assert.deepEqual(c({ stdout: pre({ permissionDecision: 'defer' }) }), ['defer', 'permission_decision']);
  assert.deepEqual(c({ stdout: pre({ permissionDecision: 'allow' }) }), ['allow', 'permission_decision']);
});

test('fields: deprecated decision approve/block, and hookSpecificOutput wins when both are set', () => {
  assert.deepEqual(c({ stdout: J({ decision: 'approve' }) }), ['allow', 'deprecated_decision']);
  assert.deepEqual(c({ stdout: J({ decision: 'block', reason: 'r' }) }), ['block', 'deprecated_decision']);
  assert.deepEqual(c({ stdout: J({ decision: 'approve', hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'ask' } }) }), ['ask', 'permission_decision']);
});

test('fields: PostToolUse decision block is block; Stop decision block and Stop additionalContext are block', () => {
  assert.deepEqual(c({ stdout: J({ decision: 'block', reason: 'r' }) }, 'PostToolUse'), ['block', 'decision_block_feedback']);
  assert.deepEqual(c({ stdout: J({ decision: 'block', reason: 'r' }) }, 'Stop'), ['block', 'decision_block']);
  assert.deepEqual(c({ stdout: J({ hookSpecificOutput: { hookEventName: 'Stop', additionalContext: 'run the tests' } }) }, 'Stop'), ['block', 'additional_context']);
});

test('fields: warn on additionalContext, systemMessage, updatedToolOutput, updatedInput', () => {
  assert.deepEqual(c({ stdout: pre({ additionalContext: 'note' }) }), ['warn', 'additional_context']);
  assert.deepEqual(c({ stdout: J({ hookSpecificOutput: { hookEventName: 'PostToolUse', additionalContext: 'note' } }) }, 'PostToolUse'), ['warn', 'additional_context']);
  assert.deepEqual(c({ stdout: J({ systemMessage: 'careful' }) }, 'Stop'), ['warn', 'system_message']);
  assert.deepEqual(c({ stdout: J({ hookSpecificOutput: { hookEventName: 'PostToolUse', updatedToolOutput: { stdout: '' } } }) }, 'PostToolUse'), ['warn', 'updated_tool_output']);
  assert.deepEqual(c({ stdout: pre({ updatedInput: { command: 'ls' } }) }), ['warn', 'updated_input']);
  assert.deepEqual(c({ stdout: pre({ additionalContext: '' }) }), ['pass', 'json_no_decision']);
});

test('fields: a PreToolUse allow carrying additionalContext stays allow with an annotation', () => {
  const v = classify(run({ stdout: pre({ permissionDecision: 'allow', additionalContext: 'fyi' }) }), { event: 'PreToolUse', onFailure: 'continue' });
  assert.deepEqual([v.outcome, v.mechanism, v.annotations], ['allow', 'permission_decision', ['additional_context']]);
});

test('multi-line JSON: several objects with a known field are invalid; without known fields it is plain text', () => {
  assert.deepEqual(c({ stdout: '{"a":1}\n\n{"decision":"block"}\n' }), ['error', 'invalid_json:multi_json']);
  assert.deepEqual(c({ stdout: '{"a":1}\n{"b":2}\n' }), ['pass', 'exit0']);
});

test('truncated stdout is invalid_json:stdout_over_cap', () => {
  assert.deepEqual(c({ stdout: pre({ permissionDecision: 'deny' }), stdoutTruncated: true }), ['error', 'invalid_json:stdout_over_cap']);
});

test('parseStdout: text not framed by braces is plain', () => {
  assert.deepEqual(parseStdout('[1,2]', false, 'PreToolUse'), { kind: 'PLAIN' });
  assert.deepEqual(parseStdout('{"a":1} trailing', false, 'PreToolUse'), { kind: 'PLAIN' });
  assert.deepEqual(parseStdout('  {"a":1}  \n', false, 'PreToolUse'), { kind: 'JSON', o: { a: 1 } });
});

test('a reason is reported for flagged outcomes', () => {
  const v = classify(run({ stdout: pre({ permissionDecision: 'ask', permissionDecisionReason: 'force push' }) }), { event: 'PreToolUse', onFailure: 'continue' });
  assert.equal(v.reason, 'force push');
  const w = classify(run({ stdout: J({ hookSpecificOutput: { hookEventName: 'Stop', additionalContext: 'show evidence' } }) }), { event: 'Stop', onFailure: 'continue' });
  assert.equal(w.reason, 'show evidence');
});

// Review: exit 2's reason is stderr unless the JSON itself makes a blocking decision [docs: Exit code 2].
test('row 6: exit 2 with a non-blocking JSON reason (allow, ask, or no decision) reports stderr', () => {
  const r = (stdout, event = 'PreToolUse') => classify(run({ exitCode: 2, stdout, stderr: 'stderr is the reason\n' }), { event, onFailure: 'continue' }).reason;
  assert.equal(r(pre({ permissionDecision: 'allow', permissionDecisionReason: 'json allow reason' })), 'stderr is the reason');
  assert.equal(r(pre({ permissionDecision: 'ask', permissionDecisionReason: 'json ask reason' })), 'stderr is the reason');
  assert.equal(r(J({ reason: 'json reason, no decision' }), 'PostToolUse'), 'stderr is the reason');
  assert.equal(r(J({ stopReason: 'json stopReason, continue not false' })), 'stderr is the reason');
  assert.equal(r(J({ decision: 'block', reason: 'json post block reason' }), 'PostToolUse'), 'json post block reason');
  assert.equal(r(J({ decision: 'block', reason: 'json deprecated block' })), 'json deprecated block');
});

test('PostToolUse: exit 2 and decision block are block with a feedback mechanism (the tool already ran)', () => {
  assert.deepEqual(c({ exitCode: 2, stderr: 'no' }, 'PostToolUse'), ['block', 'exit2_feedback']);
  assert.deepEqual(c({ stdout: J({ decision: 'block', reason: 'r' }) }, 'PostToolUse'), ['block', 'decision_block_feedback']);
  assert.deepEqual(c({ exitCode: 2, stderr: 'no' }, 'PreToolUse'), ['block', 'exit2']);
});

test('PostToolUse updatedMCPToolOutput is warn', () => {
  assert.deepEqual(c({ stdout: J({ hookSpecificOutput: { hookEventName: 'PostToolUse', updatedMCPToolOutput: { content: [] } } }) }, 'PostToolUse'),
    ['warn', 'updated_mcp_tool_output']);
});
