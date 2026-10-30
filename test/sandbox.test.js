// Isolation (e), teardown (f) and the wrapper probe (DESIGN.md §5, §11).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { replay } from '../src/replay.js';
import { hookFromFlags } from '../src/hooks.js';
import { probe, wrapperArgv, chooseIsolation, IsolationError } from '../src/sandbox.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.dirname(here);
const projectsDir = path.join(here, 'fixtures/projects');
const quiet = { write() {} };
const onlyC = { fileFilter: (f) => f.sessionUuid === 'cccccccc-0000-4000-8000-000000000003' };

const working = [];
for (const kind of ['unshare', 'bwrap']) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hr-probe-'));
  const r = await probe(kind, { tmp });
  fs.rmSync(tmp, { recursive: true, force: true });
  if (r.ok) working.push(kind); else console.log(`# sandbox: ${kind} unavailable here: ${r.reason}`);
}
const noWrapper = working.length === 0 ? 'no network wrapper (unshare/bwrap) passes the probe on this machine' : false;
if (noWrapper) console.log(`# skipping isolation tests: ${noWrapper}`);

const pgrep = (pattern) => spawnSync('pgrep', ['-f', pattern], { encoding: 'utf8' }).stdout.trim();
const waitGone = async (pattern, ms = 3000) => {
  const end = Date.now() + ms;
  while (Date.now() < end) { if (pgrep(pattern) === '') return true; await new Promise(r => setTimeout(r, 50)); }
  return pgrep(pattern) === '';
};

test('wrapperArgv builds the documented unshare and bwrap command lines', () => {
  assert.deepEqual(wrapperArgv('unshare', ['sh', '-c', 'x'], {}),
    ['unshare', '--user', '--net', '--pid', '--fork', '--kill-child', '--map-current-user', '--', 'sh', '-c', 'x']);
  assert.deepEqual(wrapperArgv('bwrap', ['sh', '-c', 'x'], {}),
    ['bwrap', '--dev-bind', '/', '/', '--unshare-net', '--unshare-pid', '--die-with-parent', '--', 'sh', '-c', 'x']);
  assert.deepEqual(wrapperArgv('bwrap', ['true'], { readonlyFs: true, tmp: '/t/x' }),
    ['bwrap', '--ro-bind', '/', '/', '--dev', '/dev', '--proc', '/proc', '--tmpfs', '/tmp', '--bind', '/t/x', '/t/x',
      '--unshare-net', '--unshare-pid', '--die-with-parent', '--', 'true']);
  assert.deepEqual(wrapperArgv(null, ['true'], {}), ['true']);
});

test('probe fails for a wrapper that does not exist', async () => {
  const r = await probe('unshare', { tmp: os.tmpdir(), binary: '/nonexistent/unshare' });
  assert.equal(r.ok, false);
});

test('chooseIsolation refuses (exit-3 error) when no wrapper passes and --allow-network is absent', async () => {
  await assert.rejects(chooseIsolation({ allowNetwork: false, candidates: [], tmp: os.tmpdir() }), IsolationError);
  const r = await chooseIsolation({ allowNetwork: true, candidates: [], tmp: os.tmpdir() });
  assert.equal(r.network, 'NOT ISOLATED');
  assert.equal(r.wrapper, null);
});

for (const kind of ['unshare', 'bwrap']) {
  const skip = !working.includes(kind) && `${kind} does not pass the network probe here`;
  if (skip) console.log(`# skipping ${kind} isolation tests: ${skip}`);

  test(`(e) ${kind}: a hook cannot connect to a port listening on the host's 127.0.0.1`, { skip }, async (t) => {
    const server = net.createServer((s) => { s.on('error', () => {}); s.end('hi'); }).listen(0, '127.0.0.1');
    await new Promise(r => server.once('listening', r));
    t.after(() => server.close());
    const port = server.address().port;
    const js = `require('net').connect(${port},'127.0.0.1').on('connect',()=>{console.log('connected');process.exit(0)}).on('error',e=>{console.log('error '+e.code);process.exit(1)})`;
    const cmd = `node -e "${js}"`;
    // Control: the same command without hook-replay does reach the port, so this test can fail.
    const control = await new Promise((resolve) => {
      const c = spawn('sh', ['-c', cmd], { stdio: ['ignore', 'pipe', 'ignore'] });
      let out = ''; c.stdout.on('data', d => { out += d; }); c.on('close', () => resolve(out));
    });
    assert.equal(control.trim(), 'connected');
    const res = await replay({ projectsDir, hooks: [hookFromFlags({ hook: cmd, event: 'PreToolUse' })], filters: onlyC, wrappers: [kind], stderr: quiet });
    assert.equal(res.isolation.network, kind);
    assert.equal(res.results.length, 1);
    assert.notEqual(res.results[0].run.stdout.trim(), 'connected');
    assert.notEqual(res.results[0].run.exitCode, 0);
  });

  test(`(f) ${kind}: a daemonising hook leaves no process behind after its timeout`, { skip }, async () => {
    const marker = `300.${process.pid}${Math.floor(Math.random() * 1e6)}`;
    const res = await replay({ projectsDir, hooks: [hookFromFlags({ hook: `setsid sleep ${marker} & sleep ${marker}`, event: 'PreToolUse', hookTimeout: '1' })],
      filters: onlyC, wrappers: [kind], stderr: quiet });
    assert.deepEqual([res.results[0].run.timedOut, res.results[0].verdict.outcome], [true, 'timeout']);
    assert.equal(await waitGone(`sleep ${marker}`), true, `a 'sleep ${marker}' survived`);
  });
}

test('(f) control: pgrep does see a setsid sleep started outside the sandbox', async () => {
  const marker = `301.${process.pid}${Math.floor(Math.random() * 1e6)}`;
  spawnSync('sh', ['-c', `setsid sleep ${marker} >/dev/null 2>&1 &`]);
  try {
    assert.notEqual(pgrep(`sleep ${marker}`), '');
  } finally {
    spawnSync('pkill', ['-f', `sleep ${marker}`]);
  }
});

test('--readonly-fs: the hook cannot write outside the temp dir (bwrap)', { skip: !working.includes('bwrap') && 'bwrap unavailable' }, async (t) => {
  const d = fs.mkdtempSync(path.join(root, '.hook-replay-rotest-'));
  t.after(() => fs.rmSync(d, { recursive: true, force: true }));
  const target = path.join(d, 'written');
  const hook = hookFromFlags({ hook: `touch ${target}`, event: 'PreToolUse' });
  const ro = await replay({ projectsDir, hooks: [hook], filters: onlyC, readonlyFs: true, stderr: quiet });
  assert.equal(ro.isolation.readonly_fs, true);
  assert.notEqual(ro.results[0].run.exitCode, 0);
  assert.equal(fs.existsSync(target), false);
  // Control: without --readonly-fs the same hook does write.
  await replay({ projectsDir, hooks: [hook], filters: onlyC, stderr: quiet });
  assert.equal(fs.existsSync(target), true);
});

test('sandbox overhead is measured and reported as p50/p95 ms', { skip: noWrapper }, async () => {
  const res = await replay({ projectsDir, hooks: [hookFromFlags({ hook: 'true', event: 'PreToolUse' })], filters: onlyC, stderr: quiet });
  assert.equal(typeof res.sandboxOverheadMs.p50, 'number');
  assert.equal(typeof res.sandboxOverheadMs.p95, 'number');
});
