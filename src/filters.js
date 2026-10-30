// Filters applied before anything runs (DESIGN.md §3 "Filters"). File-level: --project, --session.
// Point-level: --since / --until (against the line timestamp; lines without one pass) and --sample.
import crypto from 'node:crypto';
import { UsageError } from './hooks.js';

const DAY_MS = 24 * 60 * 60 * 1000;

function parseWhen(v, name, now) {
  if (v === undefined) return null;
  const m = /^(\d+)d$/.exec(v);
  if (m) return now.getTime() - Number(m[1]) * DAY_MS;
  if (!/^\d{4}-\d{2}-\d{2}/.test(v) || Number.isNaN(Date.parse(v))) throw new UsageError(`${name} must be an ISO date or Nd, got ${JSON.stringify(v)}`);
  return Date.parse(v);
}

export function parseFilters({ project, session, since, until, sample } = {}, now = new Date()) {
  const f = { project: project && project.length ? project : null, session: session ?? null,
    since: parseWhen(since, '--since', now), until: parseWhen(until, '--until', now), sample: null };
  if (sample !== undefined) {
    const r = Number(sample);
    if (!(r >= 0 && r <= 1) || sample === '') throw new UsageError('--sample must be a number in [0, 1]');
    f.sample = r;
  }
  f.raw = { project: f.project, session: f.session, since: since ?? null, until: until ?? null };
  return f;
}

// sha256(key) read as a fraction in [0, 1) from its first 52 bits.
export const sampleFraction = (key) => parseInt(crypto.createHash('sha256').update(key).digest('hex').slice(0, 13), 16) / 2 ** 52;

export function keepFile(file, f = {}) {
  if (f.project && !f.project.some(s => file.project.includes(s))) return false;
  if (f.session && file.sessionUuid !== f.session) return false;
  return true;
}

export function keepPoint(p, f = {}) {
  if (p.timestamp && (f.since != null || f.until != null)) {
    const t = Date.parse(p.timestamp);
    if (!Number.isNaN(t)) {
      if (f.since != null && t < f.since) return false;
      if (f.until != null && t > f.until) return false;
    }
  }
  if (f.sample != null && !(sampleFraction(p.key) < f.sample)) return false;
  return true;
}
