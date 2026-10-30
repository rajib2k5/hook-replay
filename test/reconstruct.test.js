import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { splitLines } from '../src/lines.js';
import { reconstruct } from '../src/reconstruct.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const PROJ = '-home-fixture-proj';
const A = `${PROJ}/aaaaaaaa-0000-4000-8000-000000000001.jsonl`;
const B = `${PROJ}/bbbbbbbb-0000-4000-8000-000000000002.jsonl`;
const BSUB = `${PROJ}/bbbbbbbb-0000-4000-8000-000000000002/subagents/agent-a1b2c3.jsonl`;
const C = `${PROJ}/cccccccc-0000-4000-8000-000000000003.jsonl`;
const E = `${PROJ}/eeeeeeee-0000-4000-8000-000000000005.jsonl`;

const fixture = (rel, opts = {}) => {
  const buf = fs.readFileSync(path.join(here, 'fixtures/projects', rel));
  const subagent = rel.includes('/subagents/');
  const sessionUuid = rel.split('/')[1].replace(/\.jsonl$/, '');
  return reconstruct(splitLines(buf), { relPath: rel, sessionUuid, subagent, homedir: '/home/fixture', ...opts });
};
// Byte offset where line n (1-based) starts, computed from the raw file.
const lineStart = (rel, n) => {
  const buf = fs.readFileSync(path.join(here, 'fixtures/projects', rel));
  let off = 0;
  for (let i = 1; i < n; i++) off = buf.indexOf(0x0a, off) + 1;
  return off;
};
const byKey = (points) => Object.fromEntries(points.map(p => [p.key, p]));

// In-memory transcript helper: one JSON object per line.
const mem = (objs, ctx = {}) => reconstruct(splitLines(Buffer.from(objs.map(o => JSON.stringify(o) + '\n').join(''))),
  { relPath: 'p/s.jsonl', sessionUuid: 's', subagent: false, homedir: '/home/fixture', ...ctx });
const asst = (uuid, id, content, stop = null, extra = {}) => ({ type: 'assistant', uuid, sessionId: 's', cwd: '/w',
  message: { id, role: 'assistant', content, stop_reason: stop }, ...extra });
const user = (uuid, content, extra = {}) => ({ type: 'user', uuid, sessionId: 's', cwd: '/w', message: { role: 'user', content }, ...extra });
const toolUse = (id, name, input) => ({ type: 'tool_use', id, name, input });
const result = (id, content, extra = {}) => ({ type: 'tool_result', tool_use_id: id, content, ...extra });

test('basic transcript: points come out in emission order (Pre after its result, Stop after what follows it)', () => {
  const { points } = fixture(A);
  assert.deepEqual(points.map(p => p.key), [
    `${A}:6:PreToolUse:toolu_A01`, `${A}:7:PostToolUse:toolu_A01`,
    `${A}:8:PreToolUse:toolu_A02`,
    `${A}:10:PreToolUse:toolu_A03`, `${A}:11:PostToolUse:toolu_A03`,
    `${A}:12:PreToolUse:toolu_A04`, `${A}:13:PostToolUse:toolu_A04`,
    `${A}:14:Stop:`,
    `${A}:18:PreToolUse:toolu_A05`, `${A}:20:PostToolUse:toolu_A05`,
    `${A}:21:PreToolUse:toolu_A06`, `${A}:22:PostToolUse:toolu_A06`,
    `${A}:23:PreToolUse:toolu_A07`,
  ]);
});

test('PreToolUse payload carries the common fields and tool fields, and no transcript_path', () => {
  const p = byKey(fixture(A).points)[`${A}:6:PreToolUse:toolu_A01`];
  assert.deepEqual(p.payload, {
    session_id: 'aaaaaaaa-0000-4000-8000-000000000001', cwd: '/home/fixture/proj', permission_mode: 'default',
    hook_event_name: 'PreToolUse', tool_name: 'Bash',
    tool_input: { command: 'rm -rf build', description: 'Remove build' }, tool_use_id: 'toolu_A01',
  });
  assert.equal(p.realSignal, 'ok');
  assert.equal(p.timestamp, '2026-10-01T10:00:02.200Z');
});

test('snapshotEnd: Pre and Stop end after their line, Post ends at the start of the result line', () => {
  const pts = byKey(fixture(A).points);
  assert.equal(pts[`${A}:6:PreToolUse:toolu_A01`].snapshotEnd, lineStart(A, 7));
  assert.equal(pts[`${A}:7:PostToolUse:toolu_A01`].snapshotEnd, lineStart(A, 7));
  assert.equal(pts[`${A}:14:Stop:`].snapshotEnd, lineStart(A, 15));
});

test('an is_error result gives Pre realSignal error and no PostToolUse point', () => {
  const { points, stats } = fixture(A);
  const pts = byKey(points);
  assert.equal(pts[`${A}:8:PreToolUse:toolu_A02`].realSignal, 'error');
  assert.equal(points.filter(p => p.payload.tool_use_id === 'toolu_A02').length, 1);
  assert.equal(stats.skipped.post_tool_use_failure, 1);
});

test('a tool_use without a result is emitted at EOF with realSignal none', () => {
  const p = byKey(fixture(A).points)[`${A}:23:PreToolUse:toolu_A07`];
  assert.equal(p.realSignal, 'none');
});

test('tool_response: toolUseResult object, else content string, else joined text blocks (flagged)', () => {
  const pts = byKey(fixture(A).points);
  const a1 = pts[`${A}:7:PostToolUse:toolu_A01`];
  assert.deepEqual(a1.payload.tool_response, { stdout: '', stderr: '', interrupted: false, isImage: false });
  assert.deepEqual(a1.fidelity, []);
  const a3 = pts[`${A}:11:PostToolUse:toolu_A03`];
  assert.equal(a3.payload.tool_response, 'done');
  assert.deepEqual(a3.fidelity, ['tool_response_from_content']);
  const a4 = pts[`${A}:13:PostToolUse:toolu_A04`];
  assert.equal(a4.payload.tool_response, '# Proj\nline two');
  assert.deepEqual(a4.fidelity, ['tool_response_from_content']);
});

test('relative file_path is resolved against cwd for Read/Write/Edit, in Pre and Post', () => {
  const pts = byKey(fixture(A).points);
  assert.equal(pts[`${A}:12:PreToolUse:toolu_A04`].payload.tool_input.file_path, '/home/fixture/proj/README.md');
  assert.equal(pts[`${A}:20:PostToolUse:toolu_A05`].payload.tool_input.file_path, '/home/fixture/proj/src/app.generated.ts');
});

test('a leading ~ in file_path / notebook_path resolves against the home dir; Bash input is untouched', () => {
  const { points } = mem([
    asst('u1', 'm1', [toolUse('t1', 'Write', { file_path: '~/x/.env' }), toolUse('t2', 'NotebookEdit', { notebook_path: 'n.ipynb' }),
      toolUse('t3', 'Bash', { command: 'cat ~/x', file_path: 'rel' })], 'tool_use'),
  ]);
  assert.deepEqual(points.map(p => p.payload.tool_input), [
    { file_path: '/home/fixture/x/.env' }, { notebook_path: '/w/n.ipynb' }, { command: 'cat ~/x', file_path: 'rel' }]);
});

test('permission_mode is the last permissionMode seen before the point', () => {
  const pts = byKey(fixture(A).points);
  assert.equal(pts[`${A}:6:PreToolUse:toolu_A01`].payload.permission_mode, 'default');
  assert.equal(pts[`${A}:18:PreToolUse:toolu_A05`].payload.permission_mode, 'acceptEdits');
  assert.equal(mem([asst('u1', 'm1', [toolUse('t1', 'Bash', {})], 'tool_use')]).points[0].payload.permission_mode, 'default');
});

test('a rewritten line repeating a tool_use id yields one Pre and one Post', () => {
  const { points, stats } = fixture(A);
  assert.equal(points.filter(p => p.payload.tool_use_id === 'toolu_A05').length, 2);
  assert.equal(stats.skipped.duplicate_tool_use_id, 1);
});

test('a duplicated uuid line is skipped, so split text is not repeated in last_assistant_message', () => {
  const { points, stats } = mem([
    user('u0', 'go'),
    asst('u1', 'm1', [{ type: 'text', text: 'first' }]),
    asst('u1', 'm1', [{ type: 'text', text: 'first' }]),
    asst('u2', 'm1', [{ type: 'text', text: 'second' }], 'end_turn'),
  ]);
  assert.equal(points.length, 1);
  assert.equal(points[0].payload.last_assistant_message, 'first\nsecond');
  assert.equal(stats.skipped.duplicate_uuid, 1);
});

test('Stop payload, stop_hook_active and realSignal over the Stop fixture', () => {
  const stops = fixture(E).points.filter(p => p.event === 'Stop');
  assert.deepEqual(stops.map(p => [p.lineNo, p.payload.stop_hook_active, p.realSignal]),
    [[5, false, 'user_prompt'], [8, false, 'assistant_continued'], [10, true, 'user_prompt'], [13, false, 'user_prompt'], [15, false, 'eof']]);
  assert.deepEqual(stops[1].payload, {
    session_id: 'eeeeeeee-0000-4000-8000-000000000005', cwd: '/home/fixture/proj', permission_mode: 'default',
    hook_event_name: 'Stop', stop_hook_active: false, last_assistant_message: 'Typo fixed and tests pass.',
    background_tasks: [], session_crons: [],
  });
});

test('isMeta user lines and tool_result lines are not real prompts for stop_hook_active', () => {
  const { points } = mem([
    user('u0', 'go'),
    asst('a1', 'm1', [{ type: 'text', text: 'one' }], 'end_turn'),
    user('u1', 'meta text', { isMeta: true }),
    asst('a2', 'm2', [{ type: 'text', text: 'two' }], 'end_turn'),
    user('u2', [{ type: 'text', text: 'real' }]),
    asst('a3', 'm3', [{ type: 'text', text: 'three' }], 'end_turn'),
  ]);
  assert.deepEqual(points.map(p => [p.payload.last_assistant_message, p.payload.stop_hook_active, p.realSignal]),
    [['one', false, 'assistant_continued'], ['two', true, 'user_prompt'], ['three', false, 'eof']]);
});

test('subagent files give Pre/Post with agent_id and never Stop; isSidechain lines count as subagent lines', () => {
  const sub = fixture(BSUB);
  assert.deepEqual(sub.points.map(p => [p.event, p.payload.agent_id]), [['PreToolUse', 'a1b2c3'], ['PostToolUse', 'a1b2c3']]);
  const main = fixture(B);
  assert.deepEqual(main.points.map(p => p.key), [
    `${B}:3:PreToolUse:toolu_B02`, `${B}:4:PostToolUse:toolu_B02`,
    `${B}:2:PreToolUse:toolu_B01`, `${B}:5:PostToolUse:toolu_B01`, `${B}:6:Stop:`]);
  assert.equal(main.points[0].payload.agent_id, 'side01');
  const noSub = fixture(B, { includeSubagents: false });
  assert.deepEqual(noSub.points.map(p => p.key), [`${B}:2:PreToolUse:toolu_B01`, `${B}:5:PostToolUse:toolu_B01`, `${B}:6:Stop:`]);
});

test('a sidechain end_turn in a main transcript does not produce Stop', () => {
  const { points } = mem([user('u0', 'go'), asst('a1', 'm1', [{ type: 'text', text: 'x' }], 'end_turn', { isSidechain: true })]);
  assert.deepEqual(points, []);
});

test('malformed, non-object, unknown-type lines are counted or skipped, and the partial last line is ignored', () => {
  const { points, stats } = fixture(C);
  assert.equal(stats.lines, 7);
  assert.equal(stats.lines_malformed, 3);
  assert.deepEqual(points.map(p => p.key), [`${C}:6:PreToolUse:toolu_C01`, `${C}:7:PostToolUse:toolu_C01`]);
});

test('oversize lines are counted and produce nothing', () => {
  const buf = Buffer.from(JSON.stringify(asst('u1', 'm1', [toolUse('t1', 'Bash', { command: 'x'.repeat(100) })], 'tool_use')) + '\n');
  const { points, stats } = reconstruct(splitLines(buf, { maxLineBytes: 50 }), { relPath: 'p/s.jsonl', sessionUuid: 's', subagent: false, homedir: '/h' });
  assert.deepEqual([points.length, stats.lines_oversize], [0, 1]);
});

test('session_id falls back to the uuid in the path; prompt_id only from the envelope', () => {
  const { points } = mem([
    { type: 'assistant', uuid: 'a1', cwd: '/w', promptId: 'p-1', message: { id: 'm1', content: [toolUse('t1', 'Bash', {})], stop_reason: 'tool_use' } },
  ], { sessionUuid: 'from-path' });
  assert.equal(points[0].payload.session_id, 'from-path');
  assert.equal(points[0].payload.prompt_id, 'p-1');
});

test('pending is bounded at 10,000: the oldest is emitted with none and its late result is not a Post', () => {
  const objs = [];
  for (let i = 0; i <= 10000; i++) objs.push(asst(`a${i}`, `m${i}`, [toolUse(`t${i}`, 'Bash', { command: `c${i}` })], 'tool_use'));
  objs.push(user('r0', [result('t0', 'late')]));
  const { points } = mem(objs);
  assert.equal(points[0].payload.tool_use_id, 't0');
  assert.equal(points[0].realSignal, 'none');
  assert.equal(points.filter(p => p.event === 'PostToolUse').length, 0);
});

test('points_by_event counts every emitted point', () => {
  assert.deepEqual(fixture(A).stats.points_by_event, { PreToolUse: 7, PostToolUse: 5, Stop: 1 });
});

// Review: silent drops and invented fields.
test('a tool_result whose tool_use is not pending is counted as orphan_tool_results', () => {
  const { points, stats } = mem([
    user('u1', [result('toolu_never', 'x')]),
    asst('a1', 'm1', [toolUse('toolu_1', 'Bash', { command: 'ls' })], 'tool_use'),
    user('u2', [result('toolu_1', 'ok')]),
    user('u3', [result('toolu_1', 'again')]),
  ]);
  assert.equal(stats.orphan_tool_results, 2);
  assert.equal(points.filter(p => p.event === 'PostToolUse').length, 1);
});

test('assistant message.content as a plain string is the Stop last_assistant_message', () => {
  const { points } = mem([user('u1', 'hi'), asst('a1', 'm1', 'All done as a string.', 'end_turn')]);
  assert.equal(points.find(p => p.event === 'Stop').payload.last_assistant_message, 'All done as a string.');
});

test('a line without cwd uses the last cwd seen in the file (also for relative paths)', () => {
  const { points } = mem([
    user('u1', 'hi', { cwd: '/seen/dir' }),
    asst('a1', 'm1', [toolUse('toolu_1', 'Read', { file_path: 'rel.txt' })], 'tool_use', { cwd: undefined }),
    user('u2', [result('toolu_1', 'ok')], { cwd: undefined }),
  ]);
  for (const p of points) {
    assert.equal(p.payload.cwd, '/seen/dir', p.key);
    assert.deepEqual(p.fidelity.filter(f => f === 'cwd_missing'), [], p.key);
  }
  assert.equal(points[0].payload.tool_input.file_path, '/seen/dir/rel.txt');
});

test('with no cwd anywhere in the file, cwd is omitted and the point carries fidelity cwd_missing', () => {
  const { points } = mem([
    user('u1', 'hi', { cwd: undefined }),
    asst('a1', 'm1', [toolUse('toolu_1', 'Bash', { command: 'ls' })], 'tool_use', { cwd: undefined }),
    user('u2', [result('toolu_1', 'ok')], { cwd: undefined }),
    asst('a2', 'm2', [{ type: 'text', text: 'done' }], 'end_turn', { cwd: undefined }),
  ]);
  assert.deepEqual(points.map(p => [p.event, 'cwd' in p.payload, p.fidelity.includes('cwd_missing')]),
    [['PreToolUse', false, true], ['PostToolUse', false, true], ['Stop', false, true]]);
});

test('agent_id only for subagent files and isSidechain lines, not for a main-session line that carries agentId', () => {
  const lines = (sidechain) => [asst('a1', 'm1', [toolUse('toolu_1', 'Bash', { command: 'ls' })], 'tool_use', { agentId: 'agentX', isSidechain: sidechain })];
  assert.equal('agent_id' in mem(lines(false)).points[0].payload, false);
  assert.equal(mem(lines(true)).points[0].payload.agent_id, 'agentX');
  assert.equal(mem(lines(false), { subagent: true }).points[0].payload.agent_id, 'agentX');
});

test('permission_mode outside the documented set becomes "default" with fidelity permission_mode_unknown', () => {
  const run = (mode) => mem([{ type: 'system', permissionMode: mode }, asst('a1', 'm1', [toolUse('toolu_1', 'Bash', { command: 'ls' })], 'tool_use')]).points[0];
  const weird = run('weirdMode');
  assert.deepEqual([weird.payload.permission_mode, weird.fidelity.includes('permission_mode_unknown')], ['default', true]);
  for (const m of ['default', 'plan', 'acceptEdits', 'auto', 'dontAsk', 'bypassPermissions']) {
    const p = run(m);
    assert.deepEqual([p.payload.permission_mode, p.fidelity.includes('permission_mode_unknown')], [m, false], m);
  }
});
