// Orchestration (DESIGN.md §5 "Scheduling"): scan, pick isolation, then run every selected (point, hook) pair
// with a per-transcript snapshot. Returns the raw results; report.js turns them into the redacted report.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { discover } from './corpus.js';
import { scan, filePoints, toolOf } from './scan.js';
import { Snapshot } from './snapshot.js';
import { runHook, buildEnv, commandArgv } from './runner.js';
import { classify } from './classify.js';
import { keepFile } from './filters.js';
import { chooseIsolation, wrapperArgv, hookBinds, measureOverhead, IsolationError } from './sandbox.js';

export { IsolationError };

export const DEFAULT_TIMEOUT_S = 10;

export function effectiveTimeout(hookTimeoutS, capS) {
  return hookTimeoutS <= capS ? { seconds: hookTimeoutS, source: 'hook' } : { seconds: capS, source: 'replay_cap' };
}

function makeTmp() {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hook-replay-'));
  fs.chmodSync(tmp, 0o700);
  for (const d of ['cwd', 'tmp', 'plugin-data']) fs.mkdirSync(path.join(tmp, d), { mode: 0o700 });
  return tmp;
}

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
    projectDir = process.cwd(), pluginRoot, env: envSource = process.env, stderr = process.stderr,
    readonlyFs = false, bwrapBinary = 'bwrap',
  } = opts;
  const files = discover(projectsDir).filter(f => keepFile(f, filters) && (!filters.fileFilter || filters.fileFilter(f)));
  const s = await scan({ files, hooks, filters, includeSubagents, maxLineBytes, homedir, limit });
  const tmp = makeTmp();
  const cleanup = () => { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* best effort */ } };
  let isolation;
  let sandboxOverheadMs;
  try {
    isolation = await chooseIsolation({ allowNetwork, readonlyFs, tmp, binary: bwrapBinary });
    sandboxOverheadMs = await measureOverhead(isolation, { tmp });
  } catch (e) {
    cleanup();
    throw e;
  }
  const total = Object.values(s.perHook).reduce((a, h) => a + h.points, 0);
  for (const h of hooks) {
    stderr.write(`hook-replay: ${h.id} ${h.command}\n  ${s.perHook[h.id].points} points, isolation ${isolation.network}, cwd ${cwdMode}\n` +
      `  replay EXECUTES this hook ${s.perHook[h.id].points} times; a hook with side effects will perform them ${s.perHook[h.id].points} times\n`);
  }

  const onSignal = (sig) => { cleanup(); process.kill(process.pid, sig); };
  process.once('SIGINT', onSignal);
  process.once('SIGTERM', onSignal);
  process.once('exit', cleanup);
  const env = buildEnv({ source: envSource, tmp, projectDir, pluginRoot, envNames });
  const byId = Object.fromEntries(hooks.map(h => [h.id, h]));
  const results = [];
  try {
    const work = files.map((f, n) => ({ f, n })).filter(({ f }) => s.selected.has(f.relPath));
    await pool(work, concurrency, async ({ f, n }) => {
      const sel = s.selected.get(f.relPath);
      const snap = new Snapshot(f.path, path.join(tmp, `t-${n}.jsonl`));
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
            let cwd = path.join(tmp, 'cwd');
            if (cwdMode === 'recorded' && typeof p.payload.cwd === 'string') {
              try { if (fs.statSync(p.payload.cwd).isDirectory()) cwd = p.payload.cwd; } catch { /* keep temp cwd */ }
            }
            const cmd = commandArgv(hook, env);
            const argv = wrapperArgv(isolation.wrapper, cmd, { readonlyFs: isolation.readonly_fs, tmp, binary: isolation.binary,
              binds: isolation.readonly_fs ? hookBinds(cmd) : [] });
            const run = await runHook({ argv, stdin, env, cwd, timeoutMs: t.seconds * 1000, timeoutSource: t.source,
              killGroup: true, extraInput: isolation.filter ? [isolation.filter] : [] });
            snap.afterRun();
            const verdict = classify(run, hook);
            results.push({ key: p.key, file: p.file, lineNo: p.lineNo, event: p.event, hookId: id, hook, tool: toolOf(p),
              sessionId: p.payload.session_id, timestamp: p.timestamp, payload: p.payload, snapshotEnd: p.snapshotEnd,
              realSignal: p.realSignal, fidelity: p.fidelity, run, verdict });
          }
        }
      } finally {
        snap.close();
      }
    });
  } finally {
    process.removeListener('SIGINT', onSignal);
    process.removeListener('SIGTERM', onSignal);
    process.removeListener('exit', cleanup);
    cleanup();
  }
  const hookOrder = Object.fromEntries(hooks.map((h, i) => [h.id, i]));
  results.sort((a, b) => Buffer.compare(Buffer.from(a.file), Buffer.from(b.file)) || a.lineNo - b.lineNo ||
    hookOrder[a.hookId] - hookOrder[b.hookId] || (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
  return { results, corpus: s.corpus, perHook: s.perHook, isolation, sandboxOverheadMs, tmpDir: tmp, total, files };
}
