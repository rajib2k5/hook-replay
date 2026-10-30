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
// /dev, the hidden /run/user/<uid> and the read-only `snap`.
export function wrapperArgv(kind, argv, { writableFs = false, work, snap, binary, binds = [], runUser = runUserDir() } = {}) {
  if (kind !== 'bwrap') return argv;
  const fsArgs = [...(writableFs ? ['--bind', '/', '/'] : ['--ro-bind', '/', '/']), '--dev', '/dev', '--proc', '/proc',
    ...(writableFs ? [] : ['--tmpfs', '/tmp']), ...(runUser ? ['--tmpfs', runUser] : []),
    ...binds.flatMap(b => ['--ro-bind', b, b]), '--bind', work, work, ...(snap ? ['--ro-bind', snap, snap] : [])];
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

// First non-loopback host address (IPv4 preferred), or null.
export function hostAddress() {
  const all = Object.values(os.networkInterfaces()).flat().filter(a => a && !a.internal);
  const v4 = all.find(a => a.family === 'IPv4' && !a.address.startsWith('169.254.'));
  const v6 = all.find(a => a.family === 'IPv6' && !/^fe80:/i.test(a.address));
  return (v4 || v6 || {}).address ?? null;
}

// Runs inside the sandbox: try every target, print {name: "connected" | "error <code>" | "timeout"}, exit 0.
const CLIENT = `const net=require('net');const ts=JSON.parse(process.argv[1]);const out={};let n=ts.length;
const done=(k,v)=>{if(k in out)return;out[k]=v;if(--n===0){console.log(JSON.stringify(out));process.exit(0)}};
for(const t of ts){let s;try{s=net.connect(t.opts)}catch(e){done(t.name,'error '+e.code);continue}
const tm=setTimeout(()=>{s.destroy();done(t.name,'timeout')},${PROBE_CONNECT_MS});
s.on('connect',()=>{clearTimeout(tm);s.destroy();done(t.name,'connected')}).on('error',e=>{clearTimeout(tm);done(t.name,'error '+e.code)})}`;

const listenOn = (...args) => new Promise((resolve, reject) => {
  const accepted = [];
  const server = net.createServer((s) => { accepted.push(1); s.on('error', () => {}); s.destroy(); });
  server.once('error', reject);
  server.listen(...args, () => resolve({ server, accepted }));
});

// Checks the real property, failing closed. Listeners: a Unix socket in tmp (which every wrapper mode binds into
// the sandbox, so only seccomp can stop the connect), TCP on 127.0.0.1 and on a non-loopback host address.
// (1) The wrapper must exit 0 for a trivial command. (2) Inside, every connect must fail with EACCES (what the
// seccomp socket() rule returns): ENOENT or ECONNREFUSED would mean only a hidden path or an empty network
// namespace, which a different socket defeats. (3) No listener may see a connection. (4) Positive control: the
// same client run unwrapped must connect to every listener, so the listeners were reachable to begin with.
// `wrap` builds the wrapped argv and `control` the unwrapped one (tests inject broken ones).
export async function probe({ work, snap, writableFs = false, binary, filter = seccompFilter(), wrap, control = (argv) => argv } = {}) {
  const w = wrap ?? ((argv) => wrapperArgv('bwrap', argv, { writableFs, work, snap, binary }));
  const extraInput = filter ? [filter] : [];
  const run = (argv, input = extraInput) => runHook({ argv, stdin: '', env: { PATH: process.env.PATH }, cwd: work, timeoutMs: 10000,
    timeoutSource: 'replay_cap', extraInput: input });
  const trivial = await run(w(['true']));
  if (trivial.spawnError) return { ok: false, reason: `bwrap: ${trivial.spawnError}` };
  if (trivial.exitCode !== 0) return { ok: false, reason: `bwrap: exit ${trivial.exitCode ?? trivial.signal} for a trivial command: ${trivial.stderr.trim().slice(0, 200)}` };
  const listeners = [];
  try {
    const sock = path.join(work, `probe-${process.pid}.sock`);
    const targets = [];
    const add = async (name, args, opts) => { listeners.push({ name, ...(await listenOn(...args)) }); targets.push({ name, opts: opts(listeners.at(-1).server) }); };
    await add('unix', [sock], () => ({ path: sock }));
    await add('tcp 127.0.0.1', [0, '127.0.0.1'], (s) => ({ port: s.address().port, host: '127.0.0.1' }));
    const host = hostAddress();
    if (host) await add('tcp host address', [0, host], (s) => ({ port: s.address().port, host }));
    const client = [process.execPath, '-e', CLIENT, JSON.stringify(targets)];
    const parse = (r) => { try { return JSON.parse(r.stdout); } catch { return null; } };
    const r = await run(w(client));
    if (r.spawnError) return { ok: false, reason: `bwrap: ${r.spawnError}` };
    if (r.exitCode !== 0) return { ok: false, reason: `bwrap: probe exit ${r.exitCode ?? r.signal}: ${r.stderr.trim().slice(0, 200)}` };
    const got = parse(r);
    if (!got) return { ok: false, reason: 'bwrap: probe printed no result' };
    const bad = targets.filter(t => got[t.name] !== 'error EACCES');
    if (bad.length) return { ok: false, reason: `bwrap: not EACCES inside: ${bad.map(t => `${t.name} ${got[t.name] ?? 'missing'}`).join(', ')}` };
    const reached = listeners.filter(l => l.accepted.length > 0);
    if (reached.length) return { ok: false, reason: `bwrap: listener reached: ${reached.map(l => l.name).join(', ')}` };
    const c = parse(await run(control(client), []));
    const unreached = targets.filter(t => !c || c[t.name] !== 'connected');
    if (unreached.length) return { ok: false, reason: `bwrap: probe control failed, unwrapped client did not connect: ${unreached.map(t => `${t.name} ${c?.[t.name] ?? 'missing'}`).join(', ')}` };
    const names = targets.map(t => t.name).join(', ');
    return { ok: true, reason: `bwrap+seccomp: socket() EACCES inside for ${names}; all connected unwrapped` };
  } finally {
    for (const l of listeners) l.server.close();
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

export async function chooseIsolation({ allowNetwork = false, writableFs = false, work, snap, binary = 'bwrap', arch = process.arch, platform = process.platform }) {
  if (allowNetwork) return { network: 'NOT ISOLATED', wrapper: null, readonly_fs: false, probe: 'not probed (--allow-network)', filter: null };
  const unavailable = (why) => new IsolationError(`no isolation available (${why}); pass --allow-network to run without it`);
  if (platform !== 'linux') throw unavailable(`isolation needs Linux bwrap, this is ${platform}`);
  const filter = seccompFilter(arch);
  if (!filter) throw unavailable(`no seccomp program for architecture ${arch}`);
  const bin = which(binary);
  const r = await probe({ work, snap, writableFs, binary: bin, filter });
  if (!r.ok) throw unavailable(r.reason);
  return { network: 'bwrap', wrapper: 'bwrap', binary: bin, readonly_fs: !writableFs, probe: r.reason, filter };
}

// Latency of `true`, 20 runs unwrapped and 20 wrapped, reported as two distributions. Differences of percentiles
// of two independent samples can come out inverted (p95 < p50) or negative, so none is reported. null unwrapped.
// `time(argv, extraInput)` returns the latencies of `runs` runs (tests inject it).
export async function measureOverhead(isolation, { work, snap, runs = 20, time } = {}) {
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
  const wrapped = summary(await timeRuns(wrapperArgv(isolation.wrapper, ['true'], { writableFs: !isolation.readonly_fs, work, snap, binary: isolation.binary }), [isolation.filter]));
  return { wrapped, unwrapped };
}
