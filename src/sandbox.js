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

export function wrapperArgv(kind, argv, { readonlyFs = false, tmp, binary, binds = [] } = {}) {
  if (kind !== 'bwrap') return argv;
  const fsArgs = readonlyFs
    ? ['--ro-bind', '/', '/', '--dev', '/dev', '--proc', '/proc', '--tmpfs', '/tmp', ...binds.flatMap(b => ['--ro-bind', b, b]), '--bind', tmp, tmp]
    : ['--dev-bind', '/', '/', '--proc', '/proc'];
  return [binary ?? 'bwrap', ...fsArgs, '--unshare-all', '--new-session', '--die-with-parent', '--seccomp', String(SECCOMP_FD), '--', ...argv];
}

// Files under /tmp that the hook command names. --readonly-fs puts a tmpfs on /tmp, so these are bound back
// read-only; files next to them are not.
export function hookBinds(argv) {
  const out = [];
  for (const tok of argv.flatMap(a => a.split(/\s+/)).map(s => s.replace(/^['"]+|['"]+$/g, ''))) {
    if (!tok.startsWith('/tmp/') || out.includes(tok)) continue;
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

// Checks the real property, failing closed: (1) a Unix socket the probe listens on in tmp, (2) TCP listeners
// on 127.0.0.1 and on a non-loopback host address must all be unreachable from inside, and (3) the wrapper
// must exit 0 for a trivial command. `wrap` builds the wrapped argv (tests inject broken wrappers).
export async function probe({ tmp, readonlyFs = false, binary, filter = seccompFilter(), wrap } = {}) {
  const w = wrap ?? ((argv) => wrapperArgv('bwrap', argv, { readonlyFs, tmp, binary }));
  const extraInput = filter ? [filter] : [];
  const run = (argv) => runHook({ argv: w(argv), stdin: '', env: { PATH: process.env.PATH }, cwd: tmp, timeoutMs: 10000,
    timeoutSource: 'replay_cap', extraInput });
  const trivial = await run(['true']);
  if (trivial.spawnError) return { ok: false, reason: `bwrap: ${trivial.spawnError}` };
  if (trivial.exitCode !== 0) return { ok: false, reason: `bwrap: exit ${trivial.exitCode ?? trivial.signal} for a trivial command: ${trivial.stderr.trim().slice(0, 200)}` };
  const listeners = [];
  try {
    const sock = path.join(tmp, `probe-${process.pid}.sock`);
    const targets = [];
    const add = async (name, args, opts) => { listeners.push({ name, ...(await listenOn(...args)) }); targets.push({ name, opts: opts(listeners.at(-1).server) }); };
    await add('unix', [sock], () => ({ path: sock }));
    await add('tcp 127.0.0.1', [0, '127.0.0.1'], (s) => ({ port: s.address().port, host: '127.0.0.1' }));
    const host = hostAddress();
    if (host) await add('tcp host address', [0, host], (s) => ({ port: s.address().port, host }));
    const r = await run([process.execPath, '-e', CLIENT, JSON.stringify(targets)]);
    if (r.spawnError) return { ok: false, reason: `bwrap: ${r.spawnError}` };
    if (r.exitCode !== 0) return { ok: false, reason: `bwrap: probe exit ${r.exitCode ?? r.signal}: ${r.stderr.trim().slice(0, 200)}` };
    let got;
    try { got = JSON.parse(r.stdout); } catch { return { ok: false, reason: 'bwrap: probe printed no result' }; }
    const bad = targets.filter(t => typeof got[t.name] !== 'string' || !got[t.name].startsWith('error '));
    if (bad.length) return { ok: false, reason: `bwrap: ${bad.map(t => `${t.name} ${got[t.name] ?? 'missing'}`).join(', ')}` };
    const reached = listeners.filter(l => l.accepted.length > 0);
    if (reached.length) return { ok: false, reason: `bwrap: listener reached: ${reached.map(l => l.name).join(', ')}` };
    return { ok: true, reason: `bwrap+seccomp: ${targets.map(t => `${t.name} ${got[t.name]}`).join(', ')}` };
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

export async function chooseIsolation({ allowNetwork = false, readonlyFs = false, tmp, binary = 'bwrap', arch = process.arch, platform = process.platform }) {
  if (allowNetwork && readonlyFs) throw new IsolationError('--readonly-fs needs the sandbox, and --allow-network runs without it; drop one');
  if (allowNetwork) return { network: 'NOT ISOLATED', wrapper: null, readonly_fs: false, probe: 'not probed (--allow-network)', filter: null };
  const unavailable = (why) => new IsolationError(`no isolation available (${why}); pass --allow-network to run without it`);
  if (platform !== 'linux') throw unavailable(`isolation needs Linux bwrap, this is ${platform}`);
  const filter = seccompFilter(arch);
  if (!filter) throw unavailable(`no seccomp program for architecture ${arch}`);
  const bin = which(binary);
  const r = await probe({ tmp, readonlyFs, binary: bin, filter });
  if (!r.ok) throw unavailable(r.reason);
  return { network: 'bwrap', wrapper: 'bwrap', binary: bin, readonly_fs: readonlyFs, probe: r.reason, filter };
}

// Wrapped minus unwrapped latency of `true`, 20 runs each.
export async function measureOverhead(isolation, { tmp, runs = 20 } = {}) {
  if (!isolation.wrapper) return { p50: 0, p95: 0 };
  const time = async (argv, extraInput) => {
    const xs = [];
    for (let i = 0; i < runs; i++) {
      const r = await runHook({ argv, stdin: '', env: { PATH: process.env.PATH }, cwd: tmp, timeoutMs: 5000, timeoutSource: 'replay_cap', extraInput });
      xs.push(r.latencyMs);
    }
    return xs;
  };
  const plain = await time(['true'], []);
  const wrapped = await time(wrapperArgv(isolation.wrapper, ['true'], { readonlyFs: isolation.readonly_fs, tmp, binary: isolation.binary }), [isolation.filter]);
  const round = (x) => Math.round(x * 100) / 100;
  return { p50: round(percentile(wrapped, 0.5) - percentile(plain, 0.5)), p95: round(percentile(wrapped, 0.95) - percentile(plain, 0.95)) };
}
