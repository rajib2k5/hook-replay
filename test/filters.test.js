import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { keepPoint, keepFile, parseFilters, sampleFraction } from '../src/filters.js';
import { scan } from '../src/scan.js';
import { discover } from '../src/corpus.js';
import { hookFromFlags } from '../src/hooks.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const projectsDir = path.join(here, 'fixtures/projects');
const NOW = new Date('2026-10-05T12:00:30.000Z');
const pt = (key, timestamp) => ({ key, timestamp });

test('--since / --until accept an ISO date or Nd and compare with the line timestamp; no timestamp passes', () => {
  const f = parseFilters({ since: '2026-10-02', until: '2026-10-04T00:00:00Z' }, NOW);
  assert.equal(keepPoint(pt('a', '2026-10-01T23:59:59Z'), f), false);
  assert.equal(keepPoint(pt('b', '2026-10-03T10:00:00Z'), f), true);
  assert.equal(keepPoint(pt('c', '2026-10-04T00:00:01Z'), f), false);
  assert.equal(keepPoint(pt('d', null), f), true);
  const g = parseFilters({ since: '2d' }, NOW);
  assert.equal(keepPoint(pt('e', '2026-10-03T12:00:31Z'), g), true);
  assert.equal(keepPoint(pt('f', '2026-10-03T12:00:29Z'), g), false);
  assert.throws(() => parseFilters({ since: 'yesterday' }, NOW), /--since/);
});

test('--sample keeps a point iff sha256(key) as a fraction is below the rate', () => {
  const key = 'p/s.jsonl:3:PreToolUse:t1';
  const frac = parseInt(crypto.createHash('sha256').update(key).digest('hex').slice(0, 13), 16) / 2 ** 52;
  assert.equal(sampleFraction(key), frac);
  assert.equal(keepPoint(pt(key, null), parseFilters({ sample: String(frac + 1e-9) }, NOW)), true);
  assert.equal(keepPoint(pt(key, null), parseFilters({ sample: String(frac) }, NOW)), false);
  assert.throws(() => parseFilters({ sample: '1.5' }, NOW), /--sample/);
});

test('--project matches a substring of the encoded project dir; --session matches the session uuid', () => {
  const file = { project: '-home-fixture-proj', sessionUuid: 'aaaa' };
  assert.equal(keepFile(file, parseFilters({ project: ['nope', 'fixture-pr'] }, NOW)), true);
  assert.equal(keepFile(file, parseFilters({ project: ['nope'] }, NOW)), false);
  assert.equal(keepFile(file, parseFilters({ session: 'aaaa' }, NOW)), true);
  assert.equal(keepFile(file, parseFilters({ session: 'bbbb' }, NOW)), false);
});

test('scan honours --limit per hook in deterministic order and reports truncated', async () => {
  const files = discover(projectsDir);
  const hooks = [hookFromFlags({ hook: 'true', event: 'PreToolUse', matcher: 'Bash' })];
  const full = await scan({ files, hooks, limit: 5000 });
  const lim = await scan({ files, hooks, limit: 5 });
  assert.equal(full.perHook.h1.points, 23);
  assert.equal(full.perHook.h1.truncated, false);
  assert.equal(lim.perHook.h1.points, 5);
  assert.equal(lim.perHook.h1.truncated, true);
  const keys = (s) => [...s.selected.values()].flatMap(m => [...m.keys()]);
  assert.deepEqual(keys(lim), keys(full).slice(0, 5));
});

test('scan with --sample is deterministic and a subset', async () => {
  const files = discover(projectsDir);
  const hooks = [hookFromFlags({ hook: 'true', event: 'PreToolUse' })];
  const filters = parseFilters({ sample: '0.5' }, NOW);
  const a = await scan({ files, hooks, filters });
  const b = await scan({ files, hooks, filters });
  const keys = (s) => [...s.selected.values()].flatMap(m => [...m.keys()]);
  assert.deepEqual(keys(a), keys(b));
  assert.ok(keys(a).length > 0 && keys(a).length < 27, String(keys(a).length));
  for (const k of keys(a)) assert.ok(sampleFraction(k) < 0.5);
});
