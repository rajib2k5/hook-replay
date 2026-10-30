// Isolation for hook runs (DESIGN.md §5): bwrap with every namespace unshared, a new session, and a seccomp
// filter that makes socket() fail, verified once by a probe that tries to connect out of the sandbox.
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { runHook } from './runner.js';
import { percentile } from './stats.js';
import { program, encode } from './seccomp.js';

export class IsolationError extends Error {}

export const SECCOMP_FD = 3;
const PROBE_CONNECT_MS = 2000;

// The encoded seccomp program for an architecture, or null when there is none (no isolation then).
export function seccompFilter(arch = process.arch) {
  const p = program(arch);
  return p ? encode(p) : null;
}

// /run/user/<uid> (D-Bus, pulse, gpg-agent, systemd --user sockets) if it exists; it is hidden in every mode.
export function runUserDir(uid = process.getuid?.()) {
  if (uid === undefined) return null;
  const d = `/run/user/${uid}`;
  try { return fs.statSync(d).isDirectory() ? d : null; } catch { return null; }
}

// Default (read-only): the host root read-only, a fresh /dev (no host /dev/pts terminals, a private /dev/shm),
// a tmpfs on /tmp (host FIFOs and sockets there are gone) and on /run/user/<uid>, only `work` (<root>/work: cwd,
// TMPDIR, plugin data) writable. So a hook cannot rewrite ~/.claude/settings.json or ~/.bashrc for something outside
// the sandbox to run later. `snap` (<root>/snap, the transcript snapshots) is bound read-only at the same path in
// every mode, last, so transcript_path resolves and the hook cannot create, replace or link entries there: the
// files hook-replay itself opens outside the sandbox. --writable-fs binds the root writable but keeps the fresh
// /dev, the hidden /run/user/<uid> and the read-only `snap`, and binds `root` (the temp root) read-only onto itself
// before `work` and `snap`: a mount point cannot be renamed (EBUSY), so the hook cannot move the root away and put a
// link at its path (round-5 review, ren.sh). An ancestor of the root can still be renamed: see snapshot.js SnapDir.
export function wrapperArgv(kind, argv, { writableFs = false, root, work, snap, binary, binds = [], runUser = runUserDir() } = {}) {
  if (kind !== 'bwrap') return argv;
  const fsArgs = [...(writableFs ? ['--bind', '/', '/'] : ['--ro-bind', '/', '/']), '--dev', '/dev', '--proc', '/proc',
    ...(writableFs ? [] : ['--tmpfs', '/tmp']), ...(runUser ? ['--tmpfs', runUser] : []),
    ...binds.flatMap(b => ['--ro-bind', b, b]), ...(writableFs && root ? ['--ro-bind', root, root] : []),
    '--bind', work, work, ...(snap ? ['--ro-bind', snap, snap] : [])];
  return [binary ?? 'bwrap', ...fsArgs, '--unshare-all', '--new-session', '--die-with-parent', '--seccomp', String(SECCOMP_FD), '--', ...argv];
}

// The directories the sandbox replaces with an empty tmpfs: /tmp (not with --writable-fs) and /run/user/<uid>.
export function hiddenDirs({ writableFs = false, runUser = runUserDir() } = {}) {
  return [...(writableFs ? [] : ['/tmp']), ...(runUser ? [runUser] : [])];
}

// Files under a hidden dir that the hook command names (a hook script kept in /tmp), bound back read-only so they
// still run; files next to them are not visible.
export function hookBinds(argv, hidden = ['/tmp']) {
  const out = [];
  for (const tok of argv.flatMap(a => a.split(/\s+/)).map(s => s.replace(/^['"]+|['"]+$/g, ''))) {
    if (!hidden.some(d => tok.startsWith(d + '/')) || out.includes(tok)) continue;
    try { if (fs.statSync(tok).isFile()) out.push(tok); } catch { /* not a file */ }
  }
  return out;
}

const external = () => Object.values(os.networkInterfaces()).flat().filter(a => a && !a.internal);
// First non-loopback host address (IPv4 preferred), or null.
export function hostAddress() {
  const v4 = external().find(a => a.family === 'IPv4' && !a.address.startsWith('169.254.'));
  return (v4 ?? { address: hostAddress6() }).address ?? null;
}

// First global or ULA IPv6 host address (not link-local fe80::/10, not ::1), or null.
export function hostAddress6() {
  return external().find(a => a.family === 'IPv6' && !/^fe[89ab]/i.test(a.address) && a.address !== '::1')?.address ?? null;
}

// Runs inside the sandbox and prints one JSON object, then exits 0: for each target {name: "connected" |
// "error <code>" | "timeout"}; "netlink": what os.networkInterfaces() got (getifaddrs opens an AF_NETLINK socket);
// "ns net" / "ns pid": the readlink of /proc/self/ns/<x>, an inode that names the namespace.
const CLIENT = `const net=require('net'),os=require('os'),fs=require('fs');const ts=JSON.parse(process.argv[1]);const out={};
const code=e=>e.info&&typeof e.info.errno==='number'?(Math.abs(e.info.errno)===13?'EACCES':'errno '+Math.abs(e.info.errno)):e.code;
try{os.networkInterfaces();out.netlink='created'}catch(e){out.netlink='error '+code(e)}
for(const k of ['net','pid'])try{out['ns '+k]=fs.readlinkSync('/proc/self/ns/'+k)}catch(e){out['ns '+k]='error '+e.code}
let n=ts.length;const fin=()=>{console.log(JSON.stringify(out));process.exit(0)};if(n===0)fin();
const done=(k,v)=>{if(k in out)return;out[k]=v;if(--n===0)fin()};
for(const t of ts){let s;try{s=net.connect(t.opts)}catch(e){done(t.name,'error '+e.code);continue}
const tm=setTimeout(()=>{s.destroy();done(t.name,'timeout')},${PROBE_CONNECT_MS});
s.on('connect',()=>{clearTimeout(tm);s.destroy();done(t.name,'connected')}).on('error',e=>{clearTimeout(tm);done(t.name,'error '+e.code)})}`;

// Families Node cannot open: AF_PACKET and raw IPv4/IPv6 sockets, tried with python3 inside the sandbox. bwrap
// drops capabilities, so past a filter that lets them through they fail with EPERM (measured here), not EACCES.
const RAW_SOCKETS = ['packet', 'raw inet', 'raw inet6'];
const RAW_CLIENT = `import socket, json, errno
out = {}
for name, args in {'packet': (17, 3, 0), 'raw inet': (2, 3, 1), 'raw inet6': (10, 3, 58)}.items():
    try:
        socket.socket(*args).close(); out[name] = 'created'
    except OSError as e:
        out[name] = 'error ' + errno.errorcode.get(e.errno, str(e.errno))
print(json.dumps(out))`;

const listenOn = (...args) => new Promise((resolve, reject) => {
  const server = net.createServer((s) => { s.on('error', () => {}); s.destroy(); });
  server.once('error', reject);
  server.listen(...args, () => resolve(server));
});

const ownNs = (k) => { try { return fs.readlinkSync(`/proc/self/ns/${k}`); } catch { return null; } };

// Checks the real property, failing closed. (1) The wrapper must exit 0 for a trivial command. (2) Inside, socket()
// must fail with EACCES (what the seccomp rule returns) for every family: connects to a Unix socket in `work`
// (bound into the sandbox in every mode, so only seccomp can stop it), TCP to 127.0.0.1 and ::1, TCP to the
// first non-loopback IPv4 and the first global/ULA IPv6 host address (if any); AF_NETLINK (os.networkInterfaces);
// and with python3 on PATH, AF_PACKET and raw IPv4/IPv6. ENOENT, ECONNREFUSED or ENETUNREACH would only show a
// hidden path or an empty network namespace, which another family or a later bind defeats. (3) The readlink of
// /proc/self/ns/net and /proc/self/ns/pid inside must differ from hook-replay's own. (4) Positive control: the
// same client run unwrapped must connect to every target it has a listener for (::1 has none when the host has no
// IPv6 loopback; inside it must still be EACCES). `wrap` builds the wrapped argv, `control` the unwrapped one,
// `python` the python3 path or null (tests inject them).
export async function probe({ root, work, snap, writableFs = false, binary, filter = seccompFilter(), wrap, control = (argv) => argv, python = which('python3') } = {}) {
  const w = wrap ?? ((argv) => wrapperArgv('bwrap', argv, { writableFs, root, work, snap, binary }));
  const extraInput = filter ? [filter] : [];
  const run = (argv, input = extraInput) => runHook({ argv, stdin: '', env: { PATH: process.env.PATH }, cwd: work, timeoutMs: 10000,
    timeoutSource: 'replay_cap', extraInput: input });
  const trivial = await run(w(['true']));
  if (trivial.spawnError) return { ok: false, reason: `bwrap: ${trivial.spawnError}` };
  if (trivial.exitCode !== 0) return { ok: false, reason: `bwrap: exit ${trivial.exitCode ?? trivial.signal} for a trivial command: ${trivial.stderr.trim().slice(0, 200)}` };
  const servers = [];
  try {
    const sock = path.join(work, `probe-${process.pid}.sock`);
    const targets = [];
    // A target with no listener (listen failed) is still tried inside, where it must be EACCES; it has no control.
    const add = async (name, args, opts) => {
      let server = null;
      try { server = await listenOn(...args); servers.push(server); } catch { /* no listener */ }
      targets.push({ name, opts: opts(server), control: !!server });
    };
    await add('unix', [sock], () => ({ path: sock }));
    await add('tcp 127.0.0.1', [0, '127.0.0.1'], (sv) => ({ port: sv?.address().port ?? 9, host: '127.0.0.1' }));
    await add('tcp6 ::1', [0, '::1'], (sv) => ({ port: sv?.address().port ?? 9, host: '::1' }));
    const host4 = hostAddress();
    const host6 = hostAddress6();
    if (host4 && host4 !== host6) await add('tcp host address', [0, host4], (sv) => ({ port: sv?.address().port ?? 9, host: host4 }));
    if (host6) await add('tcp6 host address', [0, host6], (sv) => ({ port: sv?.address().port ?? 9, host: host6 }));
    const client = [process.execPath, '-e', CLIENT, JSON.stringify(targets.map(({ name, opts }) => ({ name, opts })))];
    const parse = (r) => { try { return JSON.parse(r.stdout); } catch { return null; } };
    const r = await run(w(client));
    if (r.spawnError) return { ok: false, reason: `bwrap: ${r.spawnError}` };
    if (r.exitCode !== 0) return { ok: false, reason: `bwrap: probe exit ${r.exitCode ?? r.signal}: ${r.stderr.trim().slice(0, 200)}` };
    const got = parse(r);
    if (!got) return { ok: false, reason: 'bwrap: probe printed no result' };
    const checked = [...targets.map(t => t.name), 'netlink'];
    if (python) {
      const raw = await run(w([python, '-c', RAW_CLIENT]));
      const g = raw.exitCode === 0 ? parse(raw) : null;
      if (!g) return { ok: false, reason: `bwrap: raw-socket probe failed: exit ${raw.exitCode ?? raw.signal ?? raw.spawnError}: ${raw.stderr.trim().slice(0, 200)}` };
      Object.assign(got, Object.fromEntries(RAW_SOCKETS.map(k => [k, g[k]])));
      checked.push(...RAW_SOCKETS);
    }
    const bad = checked.filter(k => got[k] !== 'error EACCES');
    if (bad.length) return { ok: false, reason: `bwrap: not EACCES inside: ${bad.map(k => `${k} ${got[k] ?? 'missing'}`).join(', ')}` };
    for (const k of ['net', 'pid']) {
      const mine = ownNs(k);
      const inside = got[`ns ${k}`];
      if (!mine || typeof inside !== 'string' || !/^\w+:\[\d+\]$/.test(inside) || inside === mine) {
        return { ok: false, reason: `bwrap: no own ${k} namespace: /proc/self/ns/${k} is ${inside ?? 'missing'} inside, ${mine ?? 'unreadable'} in hook-replay` };
      }
    }
    const c = parse(await run(control(client), []));
    const unreached = targets.filter(t => t.control && (!c || c[t.name] !== 'connected'));
    if (unreached.length) return { ok: false, reason: `bwrap: probe control failed, unwrapped client did not connect: ${unreached.map(t => `${t.name} ${c?.[t.name] ?? 'missing'}`).join(', ')}` };
    const noListener = targets.filter(t => !t.control).map(t => t.name);
    return { ok: true, reason: `bwrap+seccomp: socket() EACCES inside for ${checked.join(', ')}; net and pid namespaces differ from hook-replay's; ` +
      `all connected unwrapped${noListener.length ? ` (no listener, so no control, for ${noListener.join(', ')})` : ''}` +
      `${python ? '' : '; AF_PACKET and raw sockets not checked (no python3)'}` };
  } finally {
    for (const sv of servers) sv.close();
  }
}

// Resolves a command name on PATH once, so a hook cannot shadow it for later runs by writing to PATH.
function which(cmd) {
  if (cmd.includes('/')) return cmd;
  for (const dir of (process.env.PATH || '').split(':')) {
    const p = path.join(dir || '.', cmd);
    try { fs.accessSync(p, fs.constants.X_OK); if (fs.statSync(p).isFile()) return p; } catch { /* next */ }
  }
  return cmd;
}

export async function chooseIsolation({ allowNetwork = false, writableFs = false, root, work, snap, binary = 'bwrap', arch = process.arch, platform = process.platform }) {
  if (allowNetwork) return { network: 'NOT ISOLATED', wrapper: null, readonly_fs: false, probe: 'not probed (--allow-network)', filter: null };
  const unavailable = (why) => new IsolationError(`no isolation available (${why}); pass --allow-network to run without it`);
  if (platform !== 'linux') throw unavailable(`isolation needs Linux bwrap, this is ${platform}`);
  const filter = seccompFilter(arch);
  if (!filter) throw unavailable(`no seccomp program for architecture ${arch}`);
  const bin = which(binary);
  const r = await probe({ root, work, snap, writableFs, binary: bin, filter });
  if (!r.ok) throw unavailable(r.reason);
  return { network: 'bwrap', wrapper: 'bwrap', binary: bin, readonly_fs: !writableFs, probe: r.reason, filter };
}

// Latency of `true`, 20 runs unwrapped and 20 wrapped, reported as two distributions. Differences of percentiles
// of two independent samples can come out inverted (p95 < p50) or negative, so none is reported. null unwrapped.
// `time(argv, extraInput)` returns the latencies of `runs` runs (tests inject it).
export async function measureOverhead(isolation, { root, work, snap, runs = 20, time } = {}) {
  if (!isolation.wrapper) return null;
  const timeRuns = time ?? (async (argv, extraInput) => {
    const xs = [];
    for (let i = 0; i < runs; i++) {
      const r = await runHook({ argv, stdin: '', env: { PATH: process.env.PATH }, cwd: work, timeoutMs: 5000, timeoutSource: 'replay_cap', extraInput });
      xs.push(r.latencyMs);
    }
    return xs;
  });
  const round = (x) => Math.round(x * 100) / 100;
  const summary = (xs) => ({ p50: round(percentile(xs, 0.5)), p95: round(percentile(xs, 0.95)) });
  const unwrapped = summary(await timeRuns(['true'], []));
  const wrapped = summary(await timeRuns(wrapperArgv(isolation.wrapper, ['true'], { writableFs: !isolation.readonly_fs, root, work, snap, binary: isolation.binary }), [isolation.filter]));
  return { wrapped, unwrapped };
}
