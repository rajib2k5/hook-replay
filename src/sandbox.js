// Network (and pid) isolation for hook runs (DESIGN.md §5): unshare preferred, else bwrap; verified by a probe.
import { runHook } from './runner.js';
import { percentile } from './stats.js';

export class IsolationError extends Error {}

const PROBE = ['sh', '-c', 'tail -n +3 /proc/net/dev'];

export function wrapperArgv(kind, argv, { readonlyFs = false, tmp, binary } = {}) {
  if (kind === 'unshare') return [binary ?? 'unshare', '--user', '--net', '--pid', '--fork', '--kill-child', '--map-current-user', '--', ...argv];
  if (kind === 'bwrap' && readonlyFs) {
    return [binary ?? 'bwrap', '--ro-bind', '/', '/', '--dev', '/dev', '--proc', '/proc', '--tmpfs', '/tmp', '--bind', tmp, tmp,
      '--unshare-net', '--unshare-pid', '--die-with-parent', '--', ...argv];
  }
  if (kind === 'bwrap') return [binary ?? 'bwrap', '--dev-bind', '/', '/', '--unshare-net', '--unshare-pid', '--die-with-parent', '--', ...argv];
  return argv;
}

// Runs the probe under the wrapper: it must succeed and list exactly the `lo` interface.
export async function probe(kind, { tmp, readonlyFs = false, binary } = {}) {
  const r = await runHook({ argv: wrapperArgv(kind, PROBE, { readonlyFs, tmp, binary }), stdin: '', env: { PATH: process.env.PATH },
    cwd: tmp, timeoutMs: 5000, timeoutSource: 'replay_cap' });
  if (r.spawnError) return { ok: false, reason: `${kind}: ${r.spawnError}` };
  if (r.exitCode !== 0) return { ok: false, reason: `${kind}: exit ${r.exitCode ?? r.signal}: ${r.stderr.trim().slice(0, 200)}` };
  const ifaces = r.stdout.split('\n').map(l => l.split(':')[0].trim()).filter(Boolean);
  if (ifaces.length !== 1 || ifaces[0] !== 'lo') return { ok: false, reason: `${kind}: interfaces visible: ${ifaces.join(',') || 'none'}` };
  return { ok: true, reason: `${kind}: only lo visible` };
}

export async function chooseIsolation({ allowNetwork = false, readonlyFs = false, tmp, candidates = ['unshare', 'bwrap'] }) {
  const tried = [];
  const list = readonlyFs ? candidates.filter(k => k === 'bwrap') : candidates;
  if (readonlyFs && list.length === 0) throw new IsolationError('--readonly-fs requires bwrap');
  for (const kind of list) {
    const r = await probe(kind, { tmp, readonlyFs });
    tried.push(r.reason);
    if (r.ok) return { network: kind, wrapper: kind, readonly_fs: readonlyFs, probe: r.reason };
  }
  if (readonlyFs) throw new IsolationError(`--readonly-fs requires a working bwrap: ${tried.join('; ')}`);
  if (allowNetwork) return { network: 'NOT ISOLATED', wrapper: null, readonly_fs: false, probe: tried.join('; ') || 'no wrapper tried' };
  throw new IsolationError(`no network isolation available (${tried.join('; ') || 'no wrapper tried'}); pass --allow-network to run without it`);
}

// Wrapped minus unwrapped latency of `true`, 20 runs each.
export async function measureOverhead(isolation, { tmp, runs = 20 } = {}) {
  if (!isolation.wrapper) return { p50: 0, p95: 0 };
  const time = async (argv) => {
    const xs = [];
    for (let i = 0; i < runs; i++) {
      const r = await runHook({ argv, stdin: '', env: { PATH: process.env.PATH }, cwd: tmp, timeoutMs: 5000, timeoutSource: 'replay_cap' });
      xs.push(r.latencyMs);
    }
    return xs;
  };
  const plain = await time(['true']);
  const wrapped = await time(wrapperArgv(isolation.wrapper, ['true'], { readonlyFs: isolation.readonly_fs, tmp }));
  const round = (x) => Math.round(x * 100) / 100;
  return { p50: round(percentile(wrapped, 0.5) - percentile(plain, 0.5)), p95: round(percentile(wrapped, 0.95) - percentile(plain, 0.95)) };
}
