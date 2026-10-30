// Pre-pass over the corpus: reconstruct every point, apply filters and matchers, and select which
// (point, hook) pairs run, honouring --limit in deterministic order. Holds only keys, not payloads.
import fs from 'node:fs';
import os from 'node:os';
import { readLines } from './lines.js';
import { Reconstructor, emptyStats } from './reconstruct.js';
import { matches } from './matcher.js';
import { keepPoint } from './filters.js';

export async function* filePoints(file, { includeSubagents = true, maxLineBytes, homedir = os.homedir() }, stats = emptyStats()) {
  const r = new Reconstructor({ relPath: file.relPath, sessionUuid: file.sessionUuid, subagent: file.subagent, homedir, includeSubagents }, stats);
  for await (const line of readLines(file.path, { maxLineBytes })) yield* r.push(line);
  yield* r.finish();
}

export const toolOf = (p) => p.event === 'Stop' ? '-' : String(p.payload.tool_name);

export function hookApplies(hook, point) {
  if (hook.event !== point.event) return false;
  return point.event === 'Stop' || matches(hook.matcher, point.payload.tool_name);
}

export async function scan({ files, hooks, filters = {}, includeSubagents = true, maxLineBytes, homedir, limit = 5000 }) {
  const stats = emptyStats();
  const sessions = new Set();
  const selected = new Map(); // relPath -> Map(pointKey -> [hookId])
  const perHook = Object.fromEntries(hooks.map(h => [h.id, { points: 0, by_tool: {}, truncated: false }]));
  let unreadable = 0;
  for (const file of files) {
    // A file we cannot open is counted and skipped; nothing of it is selected, so the run never opens it.
    try { fs.closeSync(fs.openSync(file.path, 'r')); } catch { unreadable++; continue; }
    if (!file.subagent) sessions.add(file.sessionUuid);
    const sel = new Map();
    for await (const p of filePoints(file, { includeSubagents, maxLineBytes, homedir }, stats)) {
      if (!keepPoint(p, filters)) continue;
      for (const h of hooks) {
        if (!hookApplies(h, p)) continue;
        const ph = perHook[h.id];
        if (ph.points >= limit) { ph.truncated = true; continue; }
        ph.points++;
        const t = toolOf(p);
        ph.by_tool[t] = (ph.by_tool[t] || 0) + 1;
        if (!sel.has(p.key)) sel.set(p.key, []);
        sel.get(p.key).push(h.id);
      }
    }
    if (sel.size) selected.set(file.relPath, sel);
  }
  const corpus = {
    files: files.length, files_unreadable: unreadable, lines: stats.lines, lines_malformed: stats.lines_malformed, lines_oversize: stats.lines_oversize,
    orphan_tool_results: stats.orphan_tool_results,
    sessions: sessions.size, points_by_event: stats.points_by_event,
  };
  return { corpus, stats, selected, perHook };
}
