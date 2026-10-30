// Isolation (e), teardown (f) and the isolation probe (DESIGN.md §5, §11). These tests skip only when bwrap is
// not installed; when bwrap is installed and the isolation does not hold, they fail.
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
import { probe, wrapperArgv, chooseIsolation, seccompFilter, hostAddress, hookBinds, measureOverhead, IsolationError } from '../src/sandbox.js';
import { program, encode } from '../src/seccomp.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.dirname(here);
const projectsDir = path.join(here, 'fixtures/projects');
const quiet = { write() {} };
const onlyC = { fileFilter: (f) => f.sessionUuid === 'cccccccc-0000-4000-8000-000000000003' };

const bwrapCheck = spawnSync('bwrap', ['--version'], { encoding: 'utf8' });
const noBwrap = bwrapCheck.error ? `bwrap is not installed (${bwrapCheck.error.code})` : false;
if (noBwrap) console.log(`# skipping isolation tests: ${noBwrap}`);

const tmpDir = (t, prefix = 'hr-sbx-') => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  t.after(() => fs.rmSync(d, { recursive: true, force: true }));
  return d;
};
const pgrep = (pattern) => spawnSync('pgrep', ['-f', pattern], { encoding: 'utf8' }).stdout.trim();
// A failing (f) test must not leak its sleeps into later runs.
const reap = (t, marker) => t.after(() => spawnSync('pkill', ['-f', `sleep ${marker}`]));
const waitGone = async (pattern, ms = 3000) => {
  const end = Date.now() + ms;
  while (Date.now() < end) { if (pgrep(pattern) === '') return true; await new Promise(r => setTimeout(r, 50)); }
  return pgrep(pattern) === '';
};
const listen = async (t, ...args) => {
  const server = net.createServer((s) => { s.on('error', () => {}); s.end('hi'); }).listen(...args);
  await new Promise((r, j) => { server.once('listening', r); server.once('error', j); });
  t.after(() => server.close());
  return server;
};
// A node one-liner that prints "connected" or "error <code>" for net.connect(<target>).
const connectCmd = (target) => {
  const js = `require('net').connect(${target}).on('connect',()=>{console.log('connected');process.exit(0)}).on('error',e=>{console.log('error '+e.code);process.exit(1)})`;
  return `${process.execPath} -e "${js}"`;
};
const direct = (cmd) => new Promise((resolve) => {
  const c = spawn('sh', ['-c', cmd], { stdio: ['ignore', 'pipe', 'ignore'] });
  let out = ''; c.stdout.on('data', d => { out += d; }); c.on('close', () => resolve(out.trim()));
});
const runOne = (hook, extra = {}) => replay({ projectsDir, hooks: [hookFromFlags({ event: 'PreToolUse', ...hook })], filters: onlyC, stderr: quiet, ...extra });

// Hand-derived from <linux/bpf_common.h>, <linux/seccomp.h>, <linux/audit.h> and the syscall tables:
// struct sock_filter {u16 code; u8 jt; u8 jf; u32 k} little-endian, one instruction per line.
const EXPECTED_BPF = {
  arm64: [
    '20 00 00 00 04 00 00 00', // ld [arch]
    '15 00 01 00 b7 00 00 c0', // jeq AUDIT_ARCH_AARCH64 ? +1 : +0
    '06 00 00 00 00 00 00 80', // ret KILL_PROCESS
    '20 00 00 00 00 00 00 00', // ld [nr]
    '15 00 00 01 c6 00 00 00', // jeq 198 (socket)
    '06 00 00 00 0d 00 05 00', // ret ERRNO(EACCES)
    '15 00 00 01 a9 01 00 00', // jeq 425 (io_uring_setup)
    '06 00 00 00 26 00 05 00', // ret ERRNO(ENOSYS)
    '06 00 00 00 00 00 ff 7f', // ret ALLOW
  ],
  x64: [
    '20 00 00 00 04 00 00 00',
    '15 00 01 00 3e 00 00 c0', // jeq AUDIT_ARCH_X86_64
    '06 00 00 00 00 00 00 80',
    '20 00 00 00 00 00 00 00',
    '35 00 00 01 00 00 00 40', // jge 0x40000000 (x32 ABI)
    '06 00 00 00 0d 00 05 00',
    '15 00 00 01 29 00 00 00', // jeq 41 (socket)
    '06 00 00 00 0d 00 05 00',
    '15 00 00 01 a9 01 00 00', // jeq 425 (io_uring_setup)
    '06 00 00 00 26 00 05 00',
    '06 00 00 00 00 00 ff 7f',
  ],
};
const hex = (buf) => [...buf].map(b => b.toString(16).padStart(2, '0')).join(' ');

for (const arch of ['arm64', 'x64']) {
  test(`seccomp program for ${arch} equals the hand-derived bytes`, () => {
    assert.equal(hex(encode(program(arch))), EXPECTED_BPF[arch].join(' '));
  });
}

test('seccomp: an unsupported architecture has no program, and isolation is refused there', async (t) => {
  assert.equal(program('ia32'), null);
  assert.equal(seccompFilter('riscv64'), null);
  await assert.rejects(chooseIsolation({ tmp: tmpDir(t), arch: 'riscv64' }), (e) => e instanceof IsolationError && /riscv64/.test(e.message));
});

test('wrapperArgv: bwrap with every namespace, a new session and the seccomp fd; null wrapper is the bare argv', () => {
  const ns = ['--unshare-all', '--new-session', '--die-with-parent', '--seccomp', '3', '--'];
  assert.deepEqual(wrapperArgv('bwrap', ['sh', '-c', 'x'], {}), ['bwrap', '--dev-bind', '/', '/', '--proc', '/proc', ...ns, 'sh', '-c', 'x']);
  assert.deepEqual(wrapperArgv('bwrap', ['true'], { readonlyFs: true, tmp: '/t/x', binds: ['/tmp/h.sh'] }),
    ['bwrap', '--ro-bind', '/', '/', '--dev', '/dev', '--proc', '/proc', '--tmpfs', '/tmp', '--ro-bind', '/tmp/h.sh', '/tmp/h.sh',
      '--bind', '/t/x', '/t/x', ...ns, 'true']);
  assert.deepEqual(wrapperArgv(null, ['true'], {}), ['true']);
});

test('hookBinds: existing files under /tmp named by the command are bound; other paths are not', (t) => {
  const d = tmpDir(t);
  const f = path.join(d, 'hook.sh');
  fs.writeFileSync(f, 'exit 0\n');
  assert.deepEqual(hookBinds(['sh', '-c', `sh ${f} --flag`]), [f]);
  assert.deepEqual(hookBinds(['node', f, '/usr/bin/env', path.join(d, 'missing')]), [f]);
  assert.deepEqual(hookBinds(['sh', '-c', 'echo /etc/passwd']), []);
});

test('probe fails when the bwrap binary does not exist', async (t) => {
  const r = await probe({ tmp: tmpDir(t), binary: '/nonexistent/bwrap' });
  assert.equal(r.ok, false);
});

test('--allow-network runs hooks unwrapped and labels them NOT ISOLATED: the host port is reachable', async (t) => {
  const server = await listen(t, 0, '127.0.0.1');
  const cmd = connectCmd(`${server.address().port},'127.0.0.1'`);
  const iso = await chooseIsolation({ allowNetwork: true, tmp: tmpDir(t) });
  assert.deepEqual([iso.network, iso.wrapper], ['NOT ISOLATED', null]);
  const res = await runOne({ hook: cmd }, { allowNetwork: true });
  assert.equal(res.isolation.network, 'NOT ISOLATED');
  assert.equal(res.results[0].run.stdout.trim(), 'connected');
});

test('chooseIsolation refuses (exit-3 error) when the probe fails and --allow-network is absent', async (t) => {
  await assert.rejects(chooseIsolation({ tmp: tmpDir(t), binary: '/nonexistent/bwrap' }), IsolationError);
});

test('(f) unwrapped: a hook that backgrounds a child leaves no process behind after its timeout', async (t) => {
  const marker = `302.${process.pid}${Math.floor(Math.random() * 1e6)}`;
  reap(t, marker);
  const res = await runOne({ hook: `sleep ${marker} & sleep ${marker}`, hookTimeout: '1' }, { allowNetwork: true });
  assert.deepEqual([res.results[0].run.timedOut, res.results[0].verdict.outcome], [true, 'timeout']);
  assert.equal(await waitGone(`sleep ${marker}`), true, `a 'sleep ${marker}' survived`);
});

test('(f) control: pgrep does see a setsid sleep started outside the sandbox', async () => {
  const marker = `301.${process.pid}${Math.floor(Math.random() * 1e6)}`;
  spawnSync('sh', ['-c', `setsid sleep ${marker} >/dev/null 2>&1 &`]);
  try {
    assert.notEqual(pgrep(`sleep ${marker}`), '');
  } finally {
    spawnSync('pkill', ['-f', `sleep ${marker}`]);
  }
});

const skip = noBwrap;

test('probe passes under the real bwrap wrapper', { skip }, async (t) => {
  const r = await probe({ tmp: tmpDir(t) });
  assert.equal(r.ok, true, r.reason);
});

test('probe fails when the wrapper does not isolate (every connection is attempted and checked)', { skip }, async (t) => {
  const r = await probe({ tmp: tmpDir(t), wrap: (argv) => argv });
  assert.equal(r.ok, false);
  assert.match(r.reason, /unix connected/);
});

test('probe fails when the wrapper isolates but exits non-zero', { skip }, async (t) => {
  const tmp = tmpDir(t);
  const r = await probe({ tmp, wrap: (argv) => ['sh', '-c', '"$@"; exit 9', 'sh', ...wrapperArgv('bwrap', argv, { tmp })] });
  assert.equal(r.ok, false);
  assert.match(r.reason, /exit 9/);
});

test('(e) a hook cannot connect to a Unix socket listening on the host', { skip }, async (t) => {
  const sock = path.join(tmpDir(t), 's.sock');
  await listen(t, sock);
  const cmd = connectCmd(`'${sock}'`);
  assert.equal(await direct(cmd), 'connected', 'control: reachable without hook-replay');
  const res = await runOne({ hook: cmd });
  assert.equal(res.isolation.network, 'bwrap');
  assert.equal(res.results[0].run.stdout.trim(), 'error EACCES');
});

test("(e) a hook cannot connect to a port listening on the host's 127.0.0.1", { skip }, async (t) => {
  const server = await listen(t, 0, '127.0.0.1');
  const cmd = connectCmd(`${server.address().port},'127.0.0.1'`);
  assert.equal(await direct(cmd), 'connected', 'control');
  const res = await runOne({ hook: cmd });
  assert.equal(res.results[0].run.stdout.trim(), 'error EACCES');
});

test('(e) a hook cannot connect to a port on a non-loopback host address', { skip: skip || (!hostAddress() && 'no non-loopback address') }, async (t) => {
  const addr = hostAddress();
  const server = await listen(t, 0, addr);
  const cmd = connectCmd(`${server.address().port},'${addr}'`);
  assert.equal(await direct(cmd), 'connected', 'control');
  const res = await runOne({ hook: cmd });
  assert.equal(res.results[0].run.stdout.trim(), 'error EACCES');
});

test('(e) socketpair still works, and the hook sees only the lo interface (network namespace)', { skip }, async () => {
  const js = "const s=require('child_process').spawnSync('true',{stdio:'pipe'});console.log(s.status)";
  const res = await runOne({ hook: `${process.execPath} -e "${js}"; tail -n +3 /proc/net/dev | cut -d: -f1 | tr -d ' '` });
  assert.equal(res.results[0].run.stdout, '0\nlo\n');
});

test('(e) node, sh and the three example hooks run under the sandbox', { skip }, async () => {
  const hooks = [
    hookFromFlags({ hook: `${process.execPath} -e 0 && sh -c 'exit 0'`, event: 'PreToolUse' }),
    hookFromFlags({ hook: `node ${root}/examples/hooks/deny-rm.js`, event: 'PreToolUse', matcher: 'Bash' }),
    hookFromFlags({ hook: `sh ${root}/examples/hooks/post-generated.sh`, event: 'PostToolUse', matcher: 'Edit|Write' }),
    hookFromFlags({ hook: `node ${root}/examples/hooks/stop-claims.js`, event: 'Stop', hookTimeout: '1' }),
  ].map((h, i) => ({ ...h, id: `h${i + 1}` }));
  const res = await replay({ projectsDir, hooks, stderr: quiet });
  assert.equal(res.isolation.network, 'bwrap');
  const bad = res.results.filter(r => r.verdict.outcome === 'error' && !(r.hookId === 'h4' && r.run.timedOut));
  assert.deepEqual(bad.map(r => [r.hookId, r.verdict.mechanism, r.run.stderr]), []);
  for (const id of ['h1', 'h2', 'h3', 'h4']) assert.ok(res.results.some(r => r.hookId === id), id);
});

test('(f) bwrap: a daemonising hook leaves no process behind after its timeout', { skip }, async (t) => {
  const marker = `300.${process.pid}${Math.floor(Math.random() * 1e6)}`;
  reap(t, marker);
  const res = await runOne({ hook: `setsid sleep ${marker} & sleep ${marker}`, hookTimeout: '1' });
  assert.deepEqual([res.results[0].run.timedOut, res.results[0].verdict.outcome], [true, 'timeout']);
  assert.equal(await waitGone(`sleep ${marker}`), true, `a 'sleep ${marker}' survived`);
});

test('--readonly-fs: the hook cannot write outside the temp dir (bwrap)', { skip }, async (t) => {
  const d = fs.mkdtempSync(path.join(root, '.hook-replay-rotest-'));
  t.after(() => fs.rmSync(d, { recursive: true, force: true }));
  const target = path.join(d, 'written');
  const ro = await runOne({ hook: `touch ${target}` }, { readonlyFs: true });
  assert.equal(ro.isolation.readonly_fs, true);
  assert.notEqual(ro.results[0].run.exitCode, 0);
  assert.equal(fs.existsSync(target), false);
  // Control: without --readonly-fs the same hook does write.
  await runOne({ hook: `touch ${target}` });
  assert.equal(fs.existsSync(target), true);
});

test('--readonly-fs: a hook script stored under /tmp still runs (its path is bound read-only)', { skip }, async (t) => {
  const d = tmpDir(t);
  const script = path.join(d, 'hook.sh');
  fs.writeFileSync(script, 'cat >/dev/null\necho ran\n');
  const res = await runOne({ hook: `sh ${script}` }, { readonlyFs: true });
  assert.deepEqual([res.results[0].run.exitCode, res.results[0].run.stdout], [0, 'ran\n']);
});

test('--readonly-fs with --allow-network is refused', async (t) => {
  await assert.rejects(chooseIsolation({ allowNetwork: true, readonlyFs: true, tmp: tmpDir(t) }), IsolationError);
});

test('sandbox overhead is measured and reported as p50/p95 ms', { skip }, async () => {
  const res = await runOne({ hook: 'true' });
  for (const side of ['wrapped', 'unwrapped']) {
    const { p50, p95 } = res.sandboxOverheadMs[side];
    assert.ok(typeof p50 === 'number' && p50 >= 0 && p95 >= p50, `${side} ${p50} ${p95}`);
  }
  assert.equal(fs.existsSync(res.tmpDir), false, 'temp root removed');
});

test('sandbox overhead: wrapped and unwrapped `true` are reported as two distributions, never a difference of percentiles', async () => {
  // Timings where p95(wrapped) - p95(unwrapped) < 0 < p50(wrapped) - p50(unwrapped): the old report was inverted.
  const plain = [...Array(18).fill(1), 30, 30];
  const wrapped = [...Array(18).fill(20), 21, 21];
  const time = async (argv) => (argv[0] === 'true' ? plain : wrapped);
  const o = await measureOverhead({ wrapper: 'bwrap', filter: Buffer.alloc(0) }, { tmp: '/nonexistent', time });
  assert.deepEqual(o, { wrapped: { p50: 20, p95: 21 }, unwrapped: { p50: 1, p95: 30 } });
  assert.equal(await measureOverhead({ wrapper: null }, { tmp: '/nonexistent', time }), null);
});

// Round-3 review: the probe took any "error <code>" as isolated, so a wrapper that only hid the probe's socket
// (ENOENT) and refused TCP (ECONNREFUSED) passed, and the same wrapper then reached the host's D-Bus socket.
const noSeccomp = (argv) => ['bwrap', '--dev-bind', '/', '/', '--tmpfs', '/tmp', '--unshare-net', '--', ...argv];
test('probe rejects a wrapper without seccomp that hides /tmp and unshares the network', { skip }, async (t) => {
  const r = await probe({ tmp: tmpDir(t), wrap: noSeccomp });
  assert.equal(r.ok, false, r.reason);
});

test('probe rejects the real bwrap argv with --seccomp removed', { skip }, async (t) => {
  const tmp = tmpDir(t);
  const wrap = (argv) => { const a = wrapperArgv('bwrap', argv, { tmp }); const i = a.indexOf('--seccomp'); a.splice(i, 2); return a; };
  const r = await probe({ tmp, wrap });
  assert.equal(r.ok, false, r.reason);
  assert.match(r.reason, /not EACCES/);
});

test('probe fails when its positive control cannot connect unwrapped', { skip }, async (t) => {
  const r = await probe({ tmp: tmpDir(t), control: (argv) => ['sh', '-c', 'echo "{}"'] });
  assert.equal(r.ok, false);
  assert.match(r.reason, /control/);
});

test('probe reason states what was measured', { skip }, async (t) => {
  const r = await probe({ tmp: tmpDir(t) });
  assert.equal(r.ok, true, r.reason);
  assert.match(r.reason, /socket\(\) EACCES inside for unix, tcp 127\.0\.0\.1/);
  assert.match(r.reason, /all connected unwrapped/);
});
