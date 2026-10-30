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
import { probe, wrapperArgv, chooseIsolation, seccompFilter, hostAddress, hostAddress6, hookBinds, measureOverhead, IsolationError } from '../src/sandbox.js';
import { program, encode, ARCHES } from '../src/seccomp.js';

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
  await assert.rejects(chooseIsolation({ work: tmpDir(t), arch: 'riscv64' }), (e) => e instanceof IsolationError && /riscv64/.test(e.message));
});

test('wrapperArgv: read-only root by default, --writable-fs binds / writable; both get a fresh /dev, hide /run/user/<uid>, bind snap/ read-only last', () => {
  const ns = ['--unshare-all', '--new-session', '--die-with-parent', '--seccomp', '3', '--'];
  const run = ['--tmpfs', '/run/user/1000'];
  const snap = ['--ro-bind', '/t/snap', '/t/snap'];
  assert.deepEqual(wrapperArgv('bwrap', ['true'], { work: '/t/work', snap: '/t/snap', binds: ['/tmp/h.sh'], runUser: '/run/user/1000' }),
    ['bwrap', '--ro-bind', '/', '/', '--dev', '/dev', '--proc', '/proc', '--tmpfs', '/tmp', ...run, '--ro-bind', '/tmp/h.sh', '/tmp/h.sh',
      '--bind', '/t/work', '/t/work', ...snap, ...ns, 'true']);
  assert.deepEqual(wrapperArgv('bwrap', ['sh', '-c', 'x'], { writableFs: true, work: '/t/work', snap: '/t/snap', runUser: '/run/user/1000' }),
    ['bwrap', '--bind', '/', '/', '--dev', '/dev', '--proc', '/proc', ...run, '--bind', '/t/work', '/t/work', ...snap, ...ns, 'sh', '-c', 'x']);
  // --writable-fs binds the temp root read-only onto itself, before work/ and snap/, so it cannot be renamed.
  assert.deepEqual(wrapperArgv('bwrap', ['true'], { writableFs: true, root: '/t', work: '/t/work', snap: '/t/snap', runUser: null }),
    ['bwrap', '--bind', '/', '/', '--dev', '/dev', '--proc', '/proc', '--ro-bind', '/t', '/t', '--bind', '/t/work', '/t/work', ...snap, ...ns, 'true']);
  assert.equal(wrapperArgv('bwrap', ['true'], { root: '/t', work: '/t/work', runUser: null }).includes('/t'), false, 'read-only mode: / is read-only already');
  assert.deepEqual(wrapperArgv('bwrap', ['true'], { work: '/t/x', runUser: null }),
    ['bwrap', '--ro-bind', '/', '/', '--dev', '/dev', '--proc', '/proc', '--tmpfs', '/tmp', '--bind', '/t/x', '/t/x', ...ns, 'true']);
  assert.deepEqual(wrapperArgv(null, ['true'], {}), ['true']);
});

test('hookBinds: existing files under a hidden dir (/tmp, /run/user/<uid>) named by the command are bound; other paths are not', (t) => {
  const d = tmpDir(t);
  const f = path.join(d, 'hook.sh');
  fs.writeFileSync(f, 'exit 0\n');
  assert.deepEqual(hookBinds(['sh', '-c', `sh ${f} --flag`]), [f]);
  assert.deepEqual(hookBinds(['node', f, '/usr/bin/env', path.join(d, 'missing')]), [f]);
  assert.deepEqual(hookBinds(['sh', '-c', 'echo /etc/passwd']), []);
  assert.deepEqual(hookBinds(['sh', f], ['/run/user/1000']), []);
});

test('probe fails when the bwrap binary does not exist', async (t) => {
  const r = await probe({ work: tmpDir(t), binary: '/nonexistent/bwrap' });
  assert.equal(r.ok, false);
});

test('--allow-network runs hooks unwrapped and labels them NOT ISOLATED: the host port is reachable', async (t) => {
  const server = await listen(t, 0, '127.0.0.1');
  const cmd = connectCmd(`${server.address().port},'127.0.0.1'`);
  const iso = await chooseIsolation({ allowNetwork: true, work: tmpDir(t) });
  assert.deepEqual([iso.network, iso.wrapper], ['NOT ISOLATED', null]);
  const res = await runOne({ hook: cmd }, { allowNetwork: true });
  assert.equal(res.isolation.network, 'NOT ISOLATED');
  assert.equal(res.results[0].run.stdout.trim(), 'connected');
});

test('chooseIsolation refuses (exit-3 error) when the probe fails and --allow-network is absent', async (t) => {
  await assert.rejects(chooseIsolation({ work: tmpDir(t), binary: '/nonexistent/bwrap' }), IsolationError);
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
const hasPython = !spawnSync('python3', ['-c', '0']).error;

test('probe passes under the real bwrap wrapper', { skip }, async (t) => {
  const r = await probe({ work: tmpDir(t) });
  assert.equal(r.ok, true, r.reason);
});

test('probe fails when the wrapper does not isolate (every connection is attempted and checked)', { skip }, async (t) => {
  const r = await probe({ work: tmpDir(t), wrap: (argv) => argv });
  assert.equal(r.ok, false);
  assert.match(r.reason, /unix connected/);
});

test('probe fails when the wrapper isolates but exits non-zero', { skip }, async (t) => {
  const tmp = tmpDir(t);
  const r = await probe({ work: tmp, wrap: (argv) => ['sh', '-c', '"$@"; exit 9', 'sh', ...wrapperArgv('bwrap', argv, { work: tmp })] });
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

// Read-only filesystem is the default (round 3): a hook cannot plant code that runs later outside the sandbox.
// A directory the test owns, visible inside the sandbox (not under /tmp, which the sandbox replaces with a tmpfs).
const visibleDir = (t) => {
  const base = path.resolve(root).startsWith('/tmp/') ? os.homedir() : root;
  const d = fs.mkdtempSync(path.join(base, '.hook-replay-rotest-'));
  t.after(() => fs.rmSync(d, { recursive: true, force: true }));
  return d;
};
const uid = process.getuid();

test('default: the hook can read but not write a directory outside the temp root; --writable-fs can', { skip }, async (t) => {
  const d = visibleDir(t);
  const target = path.join(d, 'written');
  const ro = await runOne({ hook: `test -d ${d} && touch ${target}; echo $?` });
  assert.equal(ro.isolation.readonly_fs, true);
  assert.notEqual(ro.results[0].run.stdout.trim(), '0');
  assert.equal(fs.existsSync(target), false);
  const rw = await runOne({ hook: `touch ${target}` }, { writableFs: true });
  assert.equal(rw.isolation.readonly_fs, false);
  assert.equal(fs.existsSync(target), true, 'control: --writable-fs writes');
});

test("default and --writable-fs: no host /dev/pts terminal can be opened for writing", { skip }, async () => {
  const host = fs.readdirSync('/dev/pts').filter(n => /^\d+$/.test(n));
  // ": >" opens for writing and writes nothing, so a broken sandbox never prints on a real terminal. The subshell
  // keeps a failed redirection from ending sh.
  const cmd = ['0', ...host].map(n => `( : > /dev/pts/${n} ) 2>/dev/null && echo open ${n}`).join('; ') + '; true';
  for (const extra of [{}, { writableFs: true }]) {
    const res = await runOne({ hook: cmd }, extra);
    assert.equal(res.results[0].run.stdout, '', JSON.stringify(extra));
  }
});

test('default and --writable-fs: /run/user/<uid> (D-Bus, ...) is an empty tmpfs', { skip: skip || (!fs.existsSync(`/run/user/${uid}`) && 'no /run/user/<uid>') }, async () => {
  const cmd = `ls -A /run/user/${uid} | wc -l; test -e /run/user/${uid}/bus && echo bus visible; true`;
  for (const extra of [{}, { writableFs: true }]) {
    const res = await runOne({ hook: cmd }, extra);
    assert.equal(res.results[0].run.stdout.trim(), '0', JSON.stringify(extra));
  }
});

test('default: a host FIFO in a sibling of the temp root cannot be written; --writable-fs control can', { skip }, async (t) => {
  const d = fs.mkdtempSync('/tmp/hr-fifo-');
  t.after(() => fs.rmSync(d, { recursive: true, force: true }));
  const fifo = path.join(d, 'f.fifo');
  assert.equal(spawnSync('mkfifo', [fifo]).status, 0);
  const fd = fs.openSync(fifo, fs.constants.O_RDONLY | fs.constants.O_NONBLOCK);
  t.after(() => fs.closeSync(fd));
  const read = () => { try { const b = Buffer.alloc(64); return b.subarray(0, fs.readSync(fd, b)).toString(); } catch (e) { return e.code; } };
  const hook = `echo pwned > ${fifo}`;
  const ro = await runOne({ hook, hookTimeout: '2' });
  assert.notEqual(ro.results[0].run.exitCode, 0);
  assert.ok(!String(read()).includes('pwned'), 'the hook reached the FIFO');
  await runOne({ hook, hookTimeout: '2' }, { writableFs: true });
  assert.equal(read(), 'pwned\n', 'control: --writable-fs reaches the FIFO');
});

// Documented residual (README "Residual risks", DESIGN §9): the kernel does not apply the read-only mount check to
// a FIFO, so one outside /tmp, /dev and /run/user/<uid> stays writable from the default sandbox. Measured here for
// $HOME and /var/tmp; if this test fails, the residual is gone and the docs must change with it.
const varTmpOk = (() => { try { fs.accessSync('/var/tmp', fs.constants.W_OK); return true; } catch { return false; } })();
for (const [where, base, why] of [['$HOME', os.homedir(), false], ['/var/tmp', '/var/tmp', !varTmpOk && '/var/tmp is not writable']]) {
  test(`default (documented residual): a host FIFO under ${where} is writable from the sandbox`, { skip: skip || why }, async (t) => {
    const d = fs.mkdtempSync(path.join(base, '.hook-replay-fifo-'));
    const fifo = path.join(d, 'f.fifo');
    assert.equal(spawnSync('mkfifo', [fifo]).status, 0);
    const fd = fs.openSync(fifo, fs.constants.O_RDONLY | fs.constants.O_NONBLOCK);
    t.after(() => { fs.closeSync(fd); fs.rmSync(d, { recursive: true, force: true }); });
    const ro = await runOne({ hook: `echo residual > ${fifo}`, hookTimeout: '2' });
    assert.equal(ro.isolation.readonly_fs, true);
    const b = Buffer.alloc(64);
    assert.equal(b.subarray(0, fs.readSync(fd, b)).toString(), 'residual\n');
  });
}

test('default: a hook script stored under /tmp still runs (its path is bound read-only)', { skip }, async (t) => {
  const d = tmpDir(t);
  const script = path.join(d, 'hook.sh');
  fs.writeFileSync(script, 'cat >/dev/null\necho ran\n');
  const res = await runOne({ hook: `sh ${script}` });
  assert.deepEqual([res.results[0].run.exitCode, res.results[0].run.stdout], [0, 'ran\n']);
});

// Round-4 review (atk2.js): the snapshots sat in the hook-writable temp root. Now the hook can write only <root>/work.
const SNAP_WRITE = 'tp=$(sed -n \'s/.*"transcript_path":"\\([^"]*\\)".*/\\1/p\'); d=$(dirname "$tp"); ' +
  'touch "$d/new" 2>/dev/null && echo created; ln -s /etc/hostname "$d/link" 2>/dev/null && echo linked; ' +
  'chmod u+w "$tp" 2>/dev/null && echo chmod; mv "$tp" "$d/moved" 2>/dev/null && echo moved; touch "$TMPDIR/w" "$CLAUDE_PLUGIN_DATA/w" ./w && echo work; ' +
  'case "$tp" in "$(dirname "$(dirname "$TMPDIR")")"/snap/*) echo layout;; esac';
test('default and --writable-fs: the hook cannot create, link, chmod or move entries in snap/; it can write work/', { skip }, async () => {
  for (const extra of [{}, { writableFs: true }]) {
    const res = await runOne({ hook: SNAP_WRITE }, extra);
    assert.equal(res.results[0].run.stdout, 'work\nlayout\n', JSON.stringify(extra) + res.results[0].run.stderr);
  }
});

test('--allow-network (control): unwrapped, the hook can write snap/, so the probe of that test is meaningful', async () => {
  const res = await runOne({ hook: SNAP_WRITE }, { allowNetwork: true });
  assert.equal(res.results[0].run.stdout, 'created\nlinked\nchmod\nmoved\nwork\nlayout\n');
  assert.ok(res.results[0].fidelity.includes('snapshot_tampered'), res.results[0].fidelity.join(','));
  assert.ok(res.warnings.some(w => /changed, replaced or removed/.test(w)), res.warnings.join('\n'));
});

test('--allow-network: unwrapped, so the filesystem is not read-only', async (t) => {
  const iso = await chooseIsolation({ allowNetwork: true, work: tmpDir(t) });
  assert.equal(iso.readonly_fs, false);
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
  const o = await measureOverhead({ wrapper: 'bwrap', filter: Buffer.alloc(0) }, { work: '/nonexistent', time });
  assert.deepEqual(o, { wrapped: { p50: 20, p95: 21 }, unwrapped: { p50: 1, p95: 30 } });
  assert.equal(await measureOverhead({ wrapper: null }, { work: '/nonexistent', time }), null);
});

// Round-3 review: the probe took any "error <code>" as isolated, so a wrapper that only hid the probe's socket
// (ENOENT) and refused TCP (ECONNREFUSED) passed, and the same wrapper then reached the host's D-Bus socket.
const noSeccomp = (argv) => ['bwrap', '--dev-bind', '/', '/', '--tmpfs', '/tmp', '--unshare-net', '--', ...argv];
test('probe rejects a wrapper without seccomp that hides /tmp and unshares the network', { skip }, async (t) => {
  const r = await probe({ work: tmpDir(t), wrap: noSeccomp });
  assert.equal(r.ok, false, r.reason);
});

test('probe rejects the real bwrap argv with --seccomp removed', { skip }, async (t) => {
  const tmp = tmpDir(t);
  const wrap = (argv) => { const a = wrapperArgv('bwrap', argv, { work: tmp }); const i = a.indexOf('--seccomp'); a.splice(i, 2); return a; };
  const r = await probe({ work: tmp, wrap });
  assert.equal(r.ok, false, r.reason);
  assert.match(r.reason, /not EACCES/);
});

test('probe fails when its positive control cannot connect unwrapped', { skip }, async (t) => {
  const r = await probe({ work: tmpDir(t), control: (argv) => ['sh', '-c', 'echo "{}"'] });
  assert.equal(r.ok, false);
  assert.match(r.reason, /control/);
});

test('probe reason states what was measured', { skip }, async (t) => {
  const r = await probe({ work: tmpDir(t) });
  assert.equal(r.ok, true, r.reason);
  assert.match(r.reason, /socket\(\) EACCES inside for unix, tcp 127\.0\.0\.1/);
  assert.match(r.reason, /all connected unwrapped/);
});

// Round-4 review (pr3.mjs, v6.mjs): the probe accepted the real filter with --share-net, and a filter that denied
// only AF_UNIX and AF_INET (with or without a network namespace); with the latter a hook reached the host over IPv6.
// A filter for this host's arch that fails socket() with EACCES only for the listed address families.
const partialFilter = (denied) => {
  const a = ARCHES[process.arch];
  const ins = (code, jt, jf, k) => ({ code, jt, jf, k: k >>> 0 });
  const p = [ins(0x20, 0, 0, 4), ins(0x15, 1, 0, a.audit), ins(0x06, 0, 0, 0x80000000), ins(0x20, 0, 0, 0),
    ins(0x15, 0, denied.length + 1, a.socket), ins(0x20, 0, 0, 16)]; // ld args[0] (domain, low word)
  denied.forEach((d, i) => p.push(ins(0x15, denied.length - i, 0, d)));
  p.push(ins(0x06, 0, 0, 0x7fff0000), ins(0x06, 0, 0, 0x0005000d));
  return encode(p);
};
const AF = { UNIX: 1, INET: 2, INET6: 10, NETLINK: 16, PACKET: 17 };
const realArgv = (work, argv) => wrapperArgv('bwrap', argv, { work });
const shareNet = (work) => (argv) => { const a = realArgv(work, argv); a.splice(a.indexOf('--unshare-all') + 1, 0, '--share-net'); return a; };
// Every namespace but pid; the host /proc stays (a new proc needs a new pid namespace).
const sharePid = (work) => (argv) => {
  const a = realArgv(work, argv);
  a.splice(a.indexOf('--unshare-all'), 1, '--unshare-user', '--unshare-ipc', '--unshare-net', '--unshare-uts', '--unshare-cgroup-try');
  a.splice(a.indexOf('--proc'), 2);
  return a;
};
const fooled = [
  ['the real filter with --share-net', (w) => ({ wrap: shareNet(w) }), /net namespace/],
  ['the real filter without a pid namespace', (w) => ({ wrap: sharePid(w) }), /pid namespace/],
  ['a filter denying only AF_UNIX and AF_INET, with a network namespace', () => ({ filter: partialFilter([AF.UNIX, AF.INET]) }), /tcp6 ::1/],
  ['a filter denying only AF_UNIX and AF_INET, with --share-net', (w) => ({ wrap: shareNet(w), filter: partialFilter([AF.UNIX, AF.INET]) }), /tcp6 ::1 connected/],
  ['a filter allowing only AF_INET6, with a network namespace', () => ({ filter: partialFilter([AF.UNIX, AF.INET, AF.NETLINK, AF.PACKET]) }), /tcp6 ::1 error ECONNREFUSED/],
  ['a filter allowing only AF_NETLINK, with a network namespace', () => ({ filter: partialFilter([AF.UNIX, AF.INET, AF.INET6, AF.PACKET]) }), /netlink created/],
];
for (const [name, opts, why] of fooled) {
  test(`probe rejects ${name}`, { skip }, async (t) => {
    const work = tmpDir(t);
    const r = await probe({ work, ...opts(work) });
    assert.equal(r.ok, false, r.reason);
    assert.match(r.reason, why);
  });
}

test('probe rejects a filter allowing only AF_PACKET (checked with python3)', { skip: skip || (!hasPython && 'python3 is not installed') }, async (t) => {
  const r = await probe({ work: tmpDir(t), filter: partialFilter([AF.UNIX, AF.INET, AF.INET6, AF.NETLINK]) });
  assert.equal(r.ok, false, r.reason);
  assert.match(r.reason, /not EACCES inside: packet (created|error EPERM)$/);
});

// A wrapper whose network namespace is real but whose "filter" is a stand-in that fails with EACCES only for
// loopback, Unix and netlink (as an LSM rule on loopback might): only the host-address targets can tell.
const LOOPBACK_ONLY = `const net=require('net'),os=require('os');const c=net.connect;
const eacces=()=>{const s=new net.Socket();process.nextTick(()=>s.emit('error',Object.assign(new Error('EACCES'),{code:'EACCES'})));return s};
net.connect=function(o){return o.path||o.host==='127.0.0.1'||o.host==='::1'?eacces():c.apply(this,arguments)};
os.networkInterfaces=()=>{throw Object.assign(new Error('EACCES'),{code:'EACCES'})};`;
test('probe rejects a sandbox that blocks only loopback: the host-address targets are needed', { skip: skip || (!hostAddress() && !hostAddress6() && 'no non-loopback address') }, async (t) => {
  const work = tmpDir(t);
  const shim = path.join(work, 'loopback-only.cjs');
  fs.writeFileSync(shim, LOOPBACK_ONLY);
  const wrap = (argv) => {
    const a = realArgv(work, argv[0] === process.execPath ? [argv[0], '--require', shim, ...argv.slice(1)] : argv);
    a.splice(a.indexOf('--seccomp'), 2);
    return a;
  };
  const r = await probe({ work, wrap, python: null });
  assert.equal(r.ok, false, r.reason);
  assert.match(r.reason, /tcp6? host address error/);
  assert.doesNotMatch(r.reason, /(unix|127\.0\.0\.1|::1|netlink) /, 'only the host targets were not EACCES');
});

test('probe passes and states each check: v6 targets, netlink and both namespaces', { skip }, async (t) => {
  const r = await probe({ work: tmpDir(t) });
  assert.equal(r.ok, true, r.reason);
  assert.match(r.reason, /tcp6 ::1/);
  if (hostAddress6()) assert.match(r.reason, /tcp6 host address/);
  assert.match(r.reason, /netlink/);
  assert.match(r.reason, /net and pid namespaces differ/);
});

// io_uring_setup is closed by the seccomp rule, not only by bytes: IORING_OP_SOCKET would make a socket without
// socket(). The x32 and arch-kill rules are verified only by bytes on an aarch64 host (DESIGN.md §5).
const IO_URING = `python3 -c "import ctypes,os
nr={'aarch64':425,'x86_64':425}[os.uname().machine]
libc=ctypes.CDLL(None,use_errno=True)
r=libc.syscall(nr,8,ctypes.create_string_buffer(120))
print(r, ctypes.get_errno())"`;
test('(e) io_uring_setup fails with ENOSYS inside the sandbox; unwrapped it does not', { skip: skip || (!hasPython && 'python3 is not installed') }, async () => {
  const control = await direct(IO_URING);
  assert.doesNotMatch(control, / 38$/, `control: unwrapped io_uring_setup gave ${control}`);
  const res = await runOne({ hook: IO_URING });
  assert.equal(res.results[0].run.stdout.trim(), '-1 38', res.results[0].run.stderr);
});
