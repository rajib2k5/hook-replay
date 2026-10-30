// An unreadable transcript is counted (corpus.files_unreadable) and skipped; the rest of the run goes on.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.dirname(here);
const fixture = path.join(here, 'fixtures/projects/-home-fixture-proj');
const A = 'aaaaaaaa-0000-4000-8000-000000000001.jsonl';
const C = 'cccccccc-0000-4000-8000-000000000003.jsonl';
const isRoot = process.getuid && process.getuid() === 0;

const setup = (t) => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'hr-unread-'));
  const proj = path.join(d, 'projects', '-home-fixture-proj');
  fs.mkdirSync(proj, { recursive: true });
  fs.copyFileSync(path.join(fixture, A), path.join(proj, A));
  fs.copyFileSync(path.join(fixture, C), path.join(proj, C));
  fs.chmodSync(path.join(proj, A), 0o000);
  t.after(() => { fs.chmodSync(path.join(proj, A), 0o600); fs.rmSync(d, { recursive: true, force: true }); });
  return path.join(d, 'projects');
};
const cli = (projects, extra) => spawnSync(process.execPath, [path.join(root, 'bin/hook-replay.js'), '--projects-dir', projects,
  '--hook', 'true', '--event', 'PreToolUse', '--allow-network', '--json', ...extra], { encoding: 'utf8' });

for (const mode of ['run', 'dry-run']) {
  test(`${mode}: an unreadable transcript is counted and skipped, not fatal`, { skip: isRoot && 'root can read mode-000 files' }, (t) => {
    const projects = setup(t);
    const r = cli(projects, mode === 'dry-run' ? ['--dry-run'] : []);
    assert.equal(r.status, 0, r.stderr);
    const m = JSON.parse(r.stdout);
    assert.equal(m.corpus.files_unreadable, 1);
    assert.equal(m.corpus.files, 2);
    if (mode === 'run') {
      assert.equal(m.hooks[0].runs, 1, 'the readable file (C, 1 PreToolUse point) still ran');
      assert.ok(m.warnings.includes('1 transcript file(s) could not be read and were skipped'));
    } else assert.equal(m.hooks[0].points, 1);
    assert.doesNotMatch(r.stderr, /\n\s+at /, 'no stack trace');
    assert.ok(!r.stderr.includes(projects), 'no raw path');
  });
}

test('corpus.orphan_tool_results counts a tool_result that arrives in a later file than its tool_use', (t) => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'hr-orphan-'));
  t.after(() => fs.rmSync(d, { recursive: true, force: true }));
  const proj = path.join(d, 'projects', 'p');
  fs.mkdirSync(proj, { recursive: true });
  const line = (o) => JSON.stringify({ sessionId: 's', cwd: '/w', ...o }) + '\n';
  fs.writeFileSync(path.join(proj, '11111111-0000-4000-8000-000000000001.jsonl'),
    line({ type: 'assistant', uuid: 'a1', message: { id: 'm1', content: [{ type: 'tool_use', id: 'toolu_X', name: 'Bash', input: { command: 'ls' } }] } }));
  fs.writeFileSync(path.join(proj, '22222222-0000-4000-8000-000000000002.jsonl'),
    line({ type: 'user', uuid: 'u1', message: { content: [{ type: 'tool_result', tool_use_id: 'toolu_X', content: 'ok' }] } }));
  const r = cli(path.join(d, 'projects'), ['--dry-run']);
  assert.equal(r.status, 0, r.stderr);
  assert.equal(JSON.parse(r.stdout).corpus.orphan_tool_results, 1);
});

// Round-5 review (fifo.sh): a hook replaced a transcript not yet processed with a FIFO, and the source open blocked
// hook-replay for good (SIGINT and SIGTERM handlers could not run). Here the test plants the FIFO itself, after the
// scan, at replay's first stderr write; the replay runs in a child so a hang fails the test instead of stalling it.
const PLANT_FIFO = `import { replay } from ${JSON.stringify(path.join(root, 'src/replay.js'))};
import { hookFromFlags } from ${JSON.stringify(path.join(root, 'src/hooks.js'))};
import fs from 'node:fs'; import { execFileSync } from 'node:child_process';
const [projects, victim] = process.argv.slice(1);
let planted = false;
const stderr = { write() { if (!planted) { planted = true; fs.unlinkSync(victim); execFileSync('mkfifo', [victim]); } } };
const res = await replay({ projectsDir: projects, hooks: [hookFromFlags({ hook: 'true', event: 'PreToolUse' })], allowNetwork: true, stderr });
console.log(JSON.stringify({ planted, unreadable: res.corpus.files_unreadable, runs: res.results.length }));`;

test('a source replaced by a FIFO after the scan is counted unreadable and skipped; the open does not block', (t) => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'hr-fifo-'));
  t.after(() => fs.rmSync(d, { recursive: true, force: true }));
  const proj = path.join(d, 'projects', '-home-fixture-proj');
  fs.mkdirSync(proj, { recursive: true });
  fs.copyFileSync(path.join(fixture, A), path.join(proj, A));
  fs.copyFileSync(path.join(fixture, C), path.join(proj, C));
  const r = spawnSync(process.execPath, ['--input-type=module', '-e', PLANT_FIFO, path.join(d, 'projects'), path.join(proj, A)],
    { encoding: 'utf8', timeout: 15000, killSignal: 'SIGKILL' });
  assert.equal(r.signal, null, `replay blocked on the FIFO (killed after 15 s): ${r.stderr}`);
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(JSON.parse(r.stdout), { planted: true, unreadable: 1, runs: 1 });
});
