// Discover transcripts under a projects dir: <proj>/<uuid>.jsonl (main) and <proj>/<uuid>/subagents/** (subagent).
// No symlinks are followed. Sorted bytewise by relative path so every run sees the same order.
import fs from 'node:fs';
import path from 'node:path';

export function discover(projectsDir) {
  const out = [];
  const walk = (rel) => {
    let entries;
    try { entries = fs.readdirSync(path.join(projectsDir, rel), { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (e.isSymbolicLink()) continue;
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory()) walk(r);
      else if (e.isFile() && e.name.endsWith('.jsonl')) out.push(r);
    }
  };
  walk('');
  out.sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
  const files = [];
  for (const relPath of out) {
    const parts = relPath.split('/');
    if (parts.length < 2) continue; // a transcript sits inside a project dir
    const subagent = parts.length > 2 && parts.includes('subagents');
    const sessionUuid = subagent ? parts[1] : parts[1].replace(/\.jsonl$/, '');
    if (parts.length > 2 && !subagent) continue;
    files.push({ path: path.join(projectsDir, relPath), relPath, project: parts[0], sessionUuid, subagent });
  }
  return files;
}
