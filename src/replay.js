// Orchestration (DESIGN.md §5 "Scheduling"): scan, pick isolation, then run every selected (point, hook) pair
// with a per-transcript snapshot. Returns the raw results; report.js turns them into the redacted report.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { discover } from './corpus.js';
import { scan, filePoints, toolOf } from './scan.js';
import { Snapshot, SnapDir, SnapDirError } from './snapshot.js';
import { SourceError } from './lines.js';
import { runHook, buildEnv, commandArgv, killRunning } from './runner.js';
import { classify } from './classify.js';
import { keepFile } from './filters.js';
import { makeRedactor, escapeControl } from './redact.js';
import { chooseIsolation, wrapperArgv, hookBinds, hiddenDirs, measureOverhead, IsolationError } from './sandbox.js';

export { IsolationError, SnapDirError };

export const DEFAULT_TIMEOUT_S = 10;
const SIGNAL_EXIT = { SIGINT: 130, SIGTERM: 143, SIGHUP: 129 };

export function effectiveTimeout(hookTimeoutS, capS) {
  return hookTimeoutS <= capS ? { seconds: hookTimeoutS, source: 'hook' } : { seconds: capS, source: 'replay_cap' };
}

// The temp root has two halves (DESIGN.md §9): snap/ holds the transcript snapshots, which hook-replay opens outside
// the sandbox, and is bound read-only into it; work/ (cwd, TMPDIR, plugin data) is the only place a sandboxed hook
// can write. hook-replay creates nothing in work/ after this and reads nothing from it.
export function makeRoot() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'hook-replay-'));
  fs.chmodSync(root, 0o700);
  const dirs = { root, snap: path.join(root, 'snap'), work: path.join(root, 'work') };
  fs.mkdirSync(dirs.snap, { mode: 0o700 });
  fs.mkdirSync(dirs.work, { mode: 0o700 });
  for (const d of ['cwd', 'tmp', 'plugin-data']) fs.mkdirSync(path.join(dirs.work, d), { mode: 0o700 });
  return dirs;
}

// What a hook did to the snapshots (only possible unwrapped, under --allow-network), as report warnings.
const TAMPER = {
  name_taken: (n) => `${n} snapshot name(s) were already taken in the temp root when hook-replay created them (planted by a hook?); new names were used and the existing entries were not opened`,
  changed: (n) => `a hook changed, replaced or removed its transcript snapshot ${n} time(s); each was recreated from the source under a new name (fidelity flag snapshot_tampered)`,
};

async function pool(items, n, fn) {
  let i = 0;
  const workers = Array.from({ length: Math.max(1, Math.min(n, items.length)) }, async () => {
    while (i < items.length) { const item = items[i++]; await fn(item); }
  });
  await Promise.all(workers);
}

export async function replay(opts) {
  const {
    projectsDir, hooks, filters = {}, includeSubagents = true, maxLineBytes, limit = 5000, homedir = os.homedir(),
    concurrency = 4, timeoutS = DEFAULT_TIMEOUT_S, cwdMode = 'temp', envNames = [], allowNetwork = false,
    projectDir = process.cwd(), pluginRoot, env: envSource = process.env, stderr = process.stderr, redact = makeRedactor(),
    writableFs = false, bwrapBinary,
  } = opts;
  const files = discover(projectsDir).filter(f => keepFile(f, filters) && (!filters.fileFilter || filters.fileFilter(f)));
  const s = await scan({ files, hooks, filters, includeSubagents, maxLineBytes, homedir, limit });
  const dirs = makeRoot();
  const { root: tmp, snap: snapDir, work } = dirs;
  // Both opened once (round-5 review, ren.sh): snapshots are created and removed through snaps (snapshot.js SnapDir),
  // and teardown removes the root by path only while the path still names the root made here.
  const snaps = new SnapDir(snapDir);
  const rootDir = new SnapDir(tmp, 'temp root');
  // Before and after each hook run both paths must still name those dirs, else SnapDirError stops the run: a hook
  // that renamed a directory above the root and rebuilt it at the old path would otherwise be given its own files as
  // transcript_path, and the check before each create alone misses it once every snapshot exists (round-6, anc.sh).
  const verifyDirs = () => { snaps.verify(); rootDir.verify(); };
  const live = new Set();
  // Kill what still runs before removing anything: a live hook can recreate files. Then unlink the snapshots still
  // open, through the snap dir fd. rmSync does not follow symlinks (it unlinks them), so a link a hook left in work/
  // cannot make it empty the link's target. If a hook (unwrapped, or an ancestor of the root under --writable-fs)
  // renamed the root, the path is not removed (it may be the hook's); snap/ and work/ are removed through the root fd,
  // then the root under the name it has now, if empty.
  let cleaned = false;
  const cleanup = () => {
    killRunning();
    if (cleaned) return;
    cleaned = true;
    for (const sn of live) sn.close();
    const rm = (p) => { try { fs.rmSync(p, { recursive: true, force: true, maxRetries: 3 }); } catch { /* best effort */ } };
    try { rootDir.verify(); rm(tmp); } catch {
      for (const d of ['snap', 'work']) rm(rootDir.at(d));
      try {
        const now = fs.readlinkSync(rootDir.via);
        const st = fs.lstatSync(now, { bigint: true });
        if (st.dev === rootDir.id.dev && st.ino === rootDir.id.ino) fs.rmdirSync(now);
      } catch { /* best effort */ }
    }
    snaps.close();
    rootDir.close();
  };
  // Installed before the probe, which already spawns sandboxes. On a signal: kill, remove, exit 128+N.
  const handlers = Object.entries(SIGNAL_EXIT).map(([sig, code]) => [sig, () => {
    cleanup();
    try { stderr.write(`hook-replay: ${sig}: stopped, hooks killed, temp files removed\n`); } catch { /* closed */ }
    process.exit(code);
  }]);
  for (const [sig, h] of handlers) process.on(sig, h);
  process.on('exit', cleanup);
  const unhook = () => {
    for (const [sig, h] of handlers) process.removeListener(sig, h);
    process.removeListener('exit', cleanup);
  };
  let isolation;
  let sandboxOverheadMs;
  try {
    isolation = await chooseIsolation({ allowNetwork, writableFs, root: tmp, work, snap: snapDir, binary: bwrapBinary });
    sandboxOverheadMs = await measureOverhead(isolation, { root: tmp, work, snap: snapDir });
  } catch (e) {
    unhook();
    cleanup();
    throw e;
  }
  const total = Object.values(s.perHook).reduce((a, h) => a + h.points, 0);
  // A hook that can write outside work/ (--writable-fs, or unwrapped under --allow-network) can swap the directories
  // above snap/ and back while other hooks run, and so feed them fake transcripts between their checks (round-6,
  // swap.cjs). One run at a time means such a hook can only fool its own run.
  const effective = writableFs || allowNetwork ? 1 : concurrency;
  const forced = effective < concurrency
    ? `--concurrency ${concurrency} lowered to 1: with ${allowNetwork ? '--allow-network' : '--writable-fs'} a hook can write outside its work dir, so hooks run one at a time`
    : null;
  if (forced) stderr.write(`hook-replay: note: ${forced}\n`);
  for (const h of hooks) {
    stderr.write(`hook-replay: ${h.id} ${escapeControl(redact(h.args ? [h.command, ...h.args].join(' ') : h.command))}\n  ${s.perHook[h.id].points} points, isolation ${isolation.network}, cwd ${cwdMode}\n` +
      `  replay EXECUTES this hook ${s.perHook[h.id].points} times; a hook with side effects will perform them ${s.perHook[h.id].points} times\n`);
  }

  const env = buildEnv({ source: envSource, work, projectDir, pluginRoot, envNames });
  const hidden = isolation.wrapper ? hiddenDirs({ writableFs: !isolation.readonly_fs }) : [];
  const byId = Object.fromEntries(hooks.map(h => [h.id, h]));
  const results = [];
  const tampered = { name_taken: 0, changed: 0 };
  const onTamper = (kind) => { tampered[kind]++; };
  try {
    const jobs = files.map((f, n) => ({ f, n })).filter(({ f }) => s.selected.has(f.relPath));
    await pool(jobs, effective, async ({ f, n }) => {
      const sel = s.selected.get(f.relPath);
      // A source that is no longer a readable regular file (a hook replaced it, a FIFO say) is counted and skipped:
      // both opens below fail before any point of it runs.
      let snap;
      try { snap = new Snapshot(f.path, snaps, `t-${n}`, { onTamper }); } catch (e) {
        if (!(e instanceof SourceError)) throw e;
        s.corpus.files_unreadable++;
        return;
      }
      live.add(snap);
      try {
        for await (const p of filePoints(f, { includeSubagents, maxLineBytes, homedir })) {
          const ids = sel.get(p.key);
          if (!ids) continue;
          snap.sync(p.snapshotEnd);
          const { session_id, ...rest } = p.payload;
          const stdin = JSON.stringify({ session_id, transcript_path: snap.dst, ...rest });
          for (const id of ids) {
            const hook = byId[id];
            const t = effectiveTimeout(hook.timeoutS, timeoutS);
            let cwd = path.join(work, 'cwd');
            if (cwdMode === 'recorded' && typeof p.payload.cwd === 'string') {
              try { if (fs.statSync(p.payload.cwd).isDirectory()) cwd = p.payload.cwd; } catch { /* keep temp cwd */ }
            }
            const cmd = commandArgv(hook, env);
            const argv = wrapperArgv(isolation.wrapper, cmd, { writableFs: !isolation.readonly_fs, root: tmp, work, snap: snapDir, binary: isolation.binary,
              binds: hookBinds(cmd, hidden) });
            verifyDirs();
            const run = await runHook({ argv, stdin, env, cwd, timeoutMs: t.seconds * 1000, timeoutSource: t.source,
              killGroup: true, extraInput: isolation.filter ? [isolation.filter] : [] });
            verifyDirs();
            const changed = snap.afterRun();
            const verdict = classify(run, hook);
            results.push({ key: p.key, file: p.file, lineNo: p.lineNo, event: p.event, hookId: id, hook, tool: toolOf(p),
              sessionId: p.payload.session_id, timestamp: p.timestamp, payload: p.payload, snapshotEnd: p.snapshotEnd,
              realSignal: p.realSignal, fidelity: changed ? [...p.fidelity, 'snapshot_tampered'] : p.fidelity, run, verdict });
          }
        }
      } catch (e) {
        if (!(e instanceof SourceError)) throw e;
        s.corpus.files_unreadable++;
      } finally {
        snap.close();
        live.delete(snap);
      }
    });
  } finally {
    unhook();
    cleanup();
  }
  const hookOrder = Object.fromEntries(hooks.map((h, i) => [h.id, i]));
  results.sort((a, b) => Buffer.compare(Buffer.from(a.file), Buffer.from(b.file)) || a.lineNo - b.lineNo ||
    hookOrder[a.hookId] - hookOrder[b.hookId] || (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
  const warnings = Object.entries(tampered).filter(([, n]) => n > 0).map(([k, n]) => TAMPER[k](n));
  if (forced) warnings.push(forced);
  return { concurrency: effective, results, corpus: s.corpus, perHook: s.perHook, isolation, sandboxOverheadMs, tmpDir: tmp, total, files, warnings };
}
