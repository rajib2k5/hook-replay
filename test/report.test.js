import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { buildReport, renderHuman, SCHEMA } from '../src/report.js';
import { makeRedactor } from '../src/redact.js';

const hook = { id: 'h1', key: 'k1', event: 'PreToolUse', matcher: 'Bash', command: 'node /home/fixture/g.js', source: '--hook', timeoutS: 600, onFailure: 'continue', ifIgnored: false };
const mk = (i, outcome, o = {}) => ({
  key: `p/s.jsonl:${i}:PreToolUse:t${i}`, file: 'p/s.jsonl', lineNo: i, event: 'PreToolUse', hookId: 'h1', hook, tool: o.tool ?? 'Bash',
  sessionId: 's', timestamp: '2026-10-01T00:00:00Z', payload: { tool_name: o.tool ?? 'Bash', tool_input: o.input ?? { command: `cmd ${i}` } },
  snapshotEnd: 0, realSignal: o.real ?? 'ok', fidelity: [],
  run: { exitCode: o.exit ?? 0, signal: null, stdout: '', stderr: o.stderr ?? '', stdoutTruncated: false, timedOut: !!o.timedOut,
    timeoutSource: o.timedOut ? 'hook' : null, spawnError: null, latencyMs: o.lat ?? i },
  verdict: { outcome, mechanism: o.mech ?? 'permission_decision', reason: o.reason ?? null },
});
const res = (results) => ({
  results, corpus: { files: 1, lines: 10, lines_malformed: 0, lines_oversize: 0, sessions: 1, points_by_event: { PreToolUse: results.length, PostToolUse: 0, Stop: 0 } },
  perHook: { h1: { points: results.length, by_tool: {}, truncated: false } },
  isolation: { network: 'unshare', readonly_fs: false, probe: 'unshare: only lo visible' }, sandboxOverheadMs: { p50: 0.5, p95: 1 },
});
const build = (results, extra = {}) => buildReport({ res: res(results), hooks: [hook], config: { timeout_s: 10, concurrency: 4, cwd_mode: 'temp', project_dir: '/home/fixture/p', filters: {}, sample: null, limit: 5000 },
  redact: makeRedactor({ homedir: '/home/fixture', username: 'fixture' }), samples: 2, now: '2026-10-29T00:00:00.000Z', warnings: [], ...extra });

test('counts, by_tool, mechanisms and flagged_real_ok per hook', () => {
  const m = build([mk(1, 'block'), mk(2, 'block', { real: 'error' }), mk(3, 'pass', { mech: 'exit0' }), mk(4, 'ask', { tool: 'Read' }), mk(5, 'allow')]);
  const h = m.hooks[0];
  assert.equal(h.runs, 5);
  assert.deepEqual(h.counts, { pass: 1, allow: 1, ask: 1, defer: 0, block: 2, warn: 0, stop: 0, error: 0, timeout: 0, replay_timeout: 0 });
  assert.deepEqual(h.by_tool, { Bash: { pass: 1, allow: 1, block: 2 }, Read: { ask: 1 } });
  assert.deepEqual(h.mechanisms, { permission_decision: 4, exit0: 1 });
  assert.equal(h.flagged_real_ok, 2);
});

test('latency is over runs that exited, not timeouts', () => {
  const m = build([mk(1, 'pass', { lat: 10 }), mk(2, 'pass', { lat: 30 }), mk(3, 'timeout', { timedOut: true, exit: null, lat: 1000 })]);
  assert.deepEqual(m.hooks[0].latency_ms, { n: 2, p50: 10, p95: 30, max: 30 });
});

test('samples: per flagged outcome, the N points with the smallest sha256(key + hook.key), with stable sample_id', () => {
  const rs = [1, 2, 3, 4, 5, 6].map(i => mk(i, 'block'));
  const m = build(rs);
  const want = rs.map(r => crypto.createHash('sha256').update(r.key + hook.key).digest('hex')).sort().slice(0, 2).map(h => h.slice(0, 12));
  assert.deepEqual(m.hooks[0].samples.map(s => s.sample_id), want);
  assert.ok(m.hooks[0].samples.every(s => s.outcome === 'block'));
  assert.equal(build([mk(1, 'pass'), mk(2, 'allow')]).hooks[0].samples.length, 0);
});

test('sample excerpts are redacted, then cut to 300 chars', () => {
  const long = 'x '.repeat(400);
  const m = build([mk(1, 'block', { input: { command: `mail alice@example.com ${long}` }, reason: `ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx ${long}` })]);
  const s = m.hooks[0].samples[0];
  assert.ok(s.tool_input.length <= 300 && s.reason.length <= 300);
  assert.match(s.tool_input, /\[REDACTED:email\]/);
  assert.match(s.reason, /^\[REDACTED:github_token\]/);
  assert.equal(s.real_signal, 'ok');
  assert.match(s.real_signal_note, /candidate false positive/);
});

test('the hook command and project dir are redacted when stored', () => {
  const m = build([mk(1, 'pass')]);
  assert.equal(m.hooks[0].command, 'node ~/g.js');
  assert.equal(m.config.project_dir, '~/p');
  assert.equal(m.redacted, true);
});

test('JSON@1 top-level shape', () => {
  const m = build([mk(1, 'pass')]);
  assert.equal(m.schema, SCHEMA);
  assert.equal(SCHEMA, 'hook-replay/report@1');
  assert.deepEqual(Object.keys(m), ['schema', 'tool_version', 'generated_at', 'redacted', 'isolation', 'config', 'corpus', 'sandbox_overhead_ms', 'warnings', 'hooks']);
  assert.deepEqual(Object.keys(m.hooks[0]), ['id', 'key', 'event', 'matcher', 'command', 'source', 'if_ignored', 'runs', 'truncated', 'counts', 'by_tool',
    'mechanisms', 'flagged_real_ok', 'latency_ms', 'samples']);
  assert.ok(m.warnings.some(w => /counterfactual/i.test(w)));
});

test('human output has the table row and escapes control characters from transcripts', () => {
  const m = build([mk(1, 'block', { reason: 'hook said \x1b[31mred' }), mk(2, 'ask'), mk(3, 'pass')]);
  const out = renderHuman(m);
  assert.match(out, /HOOK\s+EVENT\s+MATCHER\s+RUNS\s+BLOCK\s+ASK\s+WARN\s+STOP\s+DEFER\s+ERROR\s+TIMEOUT\s+RTO\s+P50ms\s+P95ms\s+MAXms/);
  assert.match(out, /h1\s+PreToolUse\s+Bash\s+3\s+1\s+1\s+0\s+0\s+0\s+0\s+0\s+0\s+2\s+3\s+3/);
  assert.ok(!out.includes('\x1b'));
  assert.match(out, /\\x1b\[31mred/);
});

test('a PostToolUse block (exit2_feedback / decision_block_feedback) says it is feedback; a PreToolUse block does not', () => {
  const m = build([mk(1, 'block', { mech: 'exit2_feedback' }), mk(2, 'block', { mech: 'decision_block_feedback' }), mk(3, 'block', { mech: 'exit2' })], { samples: 5 });
  const effects = Object.fromEntries(m.hooks[0].samples.map(s => [s.mechanism, s.effect ?? null]));
  assert.deepEqual(effects, { exit2_feedback: 'feedback to Claude; the tool already ran',
    decision_block_feedback: 'feedback to Claude; the tool already ran', exit2: null });
  assert.equal(renderHuman(m).split('\n').filter(l => l.trim() === 'effect: feedback to Claude; the tool already ran').length, 2);
});
