// Teardown on signals (DESIGN.md §5 "Snapshot"): SIGINT, SIGTERM and SIGHUP to hook-replay kill the running
// hooks, remove the temp root and exit 128+N. Each run gets its own TMPDIR, so the check sees only its own root.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.dirname(here);
const projects = path.join(here, 'fixtures/projects');
const hasBwrap = !spawnSync('bwrap', ['--version']).error;

const pgrep = (pattern) => spawnSync('pgrep', ['-f', pattern], { encoding: 'utf8' }).stdout.trim();
const until = async (cond, ms = 10000) => {
  const end = Date.now() + ms;
  while (Date.now() < end) { if (cond()) return true; await new Promise(r => setTimeout(r, 50)); }
  return cond();
};

const cases = [['SIGINT', 130, true], ['SIGTERM', 143, true], ['SIGHUP', 129, true], ['SIGTERM', 143, false]];
for (const [sig, code, allowNetwork] of cases) {
  const mode = allowNetwork ? 'unwrapped' : 'bwrap';
  test(`${sig} (${mode}): the hook dies, the temp root is removed, exit ${code}`, { skip: !allowNetwork && !hasBwrap && 'bwrap is not installed' }, async (t) => {
    const d = fs.mkdtempSync(path.join(os.tmpdir(), 'hr-sig-'));
    const marker = `303.${process.pid}${Math.floor(Math.random() * 1e6)}`;
    t.after(() => { spawnSync('pkill', ['-f', `sleep ${marker}`]); fs.rmSync(d, { recursive: true, force: true }); });
    const started = path.join(d, 'started');
    const tmpdir = path.join(d, 'tmpdir');
    fs.mkdirSync(tmpdir);
    // The hook backgrounds one sleep (stays in its process group) and then hangs in another.
    const hook = `touch ${started}; sleep ${marker} & sleep ${marker}`;
    const child = spawn(process.execPath, [path.join(root, 'bin/hook-replay.js'), '--projects-dir', projects, '--session', 'cccccccc-0000-4000-8000-000000000003',
      '--hook', hook, '--event', 'PreToolUse', '--timeout', '60', ...(allowNetwork ? ['--allow-network'] : [])],
    { env: { ...process.env, TMPDIR: tmpdir }, stdio: ['ignore', 'pipe', 'pipe'] });
    const exited = new Promise(r => child.on('exit', (c, s) => r({ c, s })));
    assert.ok(await until(() => fs.existsSync(started)), 'hook started');
    assert.equal(fs.readdirSync(tmpdir).filter(n => n.startsWith('hook-replay-')).length, 1, 'temp root exists while running');
    child.kill(sig);
    const { c, s } = await exited;
    assert.ok(await until(() => pgrep(`sleep ${marker}`) === '', 3000), `a 'sleep ${marker}' survived`);
    assert.deepEqual(fs.readdirSync(tmpdir), [], 'temp root removed');
    assert.deepEqual({ code: c, signal: s }, { code, signal: null });
  });
}

test('the temp root is 0700 and its subdirectories are not group/world readable', async (t) => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'hr-perm-'));
  t.after(() => fs.rmSync(d, { recursive: true, force: true }));
  const out = path.join(d, 'modes');
  const hook = `stat -c %a "$(dirname "$TMPDIR")" "$TMPDIR" "$CLAUDE_PLUGIN_DATA" "$PWD" > ${out}`;
  const r = spawnSync(process.execPath, [path.join(root, 'bin/hook-replay.js'), '--projects-dir', projects, '--session', 'cccccccc-0000-4000-8000-000000000003',
    '--hook', hook, '--event', 'PreToolUse', '--allow-network'], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  assert.equal(fs.readFileSync(out, 'utf8'), '700\n700\n700\n700\n');
});

test('SIGTERM while the isolation probe runs still removes the temp root', { skip: !hasBwrap && 'bwrap is not installed' }, async (t) => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'hr-sig-'));
  t.after(() => fs.rmSync(d, { recursive: true, force: true }));
  const child = spawn(process.execPath, [path.join(root, 'bin/hook-replay.js'), '--projects-dir', projects, '--session', 'cccccccc-0000-4000-8000-000000000003',
    '--hook', 'true', '--event', 'PreToolUse'], { env: { ...process.env, TMPDIR: d }, stdio: ['ignore', 'pipe', 'pipe'] });
  let banner = '';
  child.stderr.on('data', (x) => { banner += x; });
  const exited = new Promise(r => child.on('exit', (c, s) => r({ c, s })));
  assert.ok(await until(() => fs.readdirSync(d).some(n => n.startsWith('hook-replay-')), 10000), 'temp root created');
  child.kill('SIGTERM');
  const { c } = await exited;
  assert.doesNotMatch(banner, /replay EXECUTES/, 'the signal arrived before any hook ran');
  assert.deepEqual(fs.readdirSync(d), []);
  assert.equal(c, 143);
});
