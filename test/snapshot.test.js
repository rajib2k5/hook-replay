import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { Snapshot } from '../src/snapshot.js';

const setup = (t) => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'hr-snap-'));
  t.after(() => fs.rmSync(d, { recursive: true, force: true }));
  const src = path.join(d, 'src.jsonl');
  fs.writeFileSync(src, 'line-one\nline-two\nline-three\n');
  return { src, dir: d };
};

test('sync appends source bytes up to snapshotEnd, and truncates when a point is released late', (t) => {
  const { src, dir } = setup(t);
  const s = new Snapshot(src, dir);
  const dst = s.dst;
  assert.equal(dst, path.join(dir, 't-0.jsonl'));
  s.sync(18);
  assert.equal(fs.readFileSync(dst, 'utf8'), 'line-one\nline-two\n');
  s.sync(9);
  assert.equal(fs.readFileSync(dst, 'utf8'), 'line-one\n');
  s.sync(29);
  assert.equal(fs.readFileSync(dst, 'utf8'), 'line-one\nline-two\nline-three\n');
  assert.equal(fs.statSync(dst).mode & 0o777, 0o400, 'read-only while a hook runs');
  s.close();
  assert.equal(fs.existsSync(dst), false);
});

test('a snapshot changed by the hook is recreated from source, under a new name', (t) => {
  const { src, dir } = setup(t);
  const s = new Snapshot(src, dir);
  s.sync(18);
  const first = s.dst;
  if (process.getuid() !== 0) assert.throws(() => fs.writeFileSync(first, 'tampered'), { code: 'EACCES' });
  fs.chmodSync(first, 0o600);
  fs.writeFileSync(first, 'tampered');
  assert.equal(s.afterRun(), true);
  assert.notEqual(s.dst, first);
  assert.equal(fs.existsSync(first), false, 'the changed file is unlinked');
  assert.equal(fs.readFileSync(s.dst, 'utf8'), 'line-one\nline-two\n');
  fs.chmodSync(s.dst, 0o600);
  fs.appendFileSync(s.dst, 'extra\n');
  s.afterRun();
  s.sync(29);
  assert.equal(fs.readFileSync(s.dst, 'utf8'), 'line-one\nline-two\nline-three\n');
  assert.equal(s.afterRun(), false, 'unchanged');
  s.close();
});

test('a same-size rewrite by the hook is detected and undone, even with the mtime put back', (t) => {
  const { src, dir } = setup(t);
  const s = new Snapshot(src, dir);
  s.sync(18);
  const dst = s.dst;
  // touch -r copies the timestamps to the nanosecond, as a careful hook could.
  const ref = `${dst}.ref`;
  fs.writeFileSync(ref, '');
  spawnSync('touch', ['-r', dst, ref]);
  const before = fs.statSync(dst, { bigint: true });
  fs.chmodSync(dst, 0o600);
  fs.writeFileSync(dst, 'X'.repeat(18));
  fs.chmodSync(dst, 0o400);
  spawnSync('touch', ['-r', ref, dst]);
  const after = fs.statSync(dst, { bigint: true });
  assert.deepEqual([after.size, after.mtimeNs, after.mode], [before.size, before.mtimeNs, before.mode], 'size, mtime and mode put back');
  s.afterRun();
  assert.equal(fs.readFileSync(s.dst, 'utf8'), 'line-one\nline-two\n');
  assert.equal(fs.statSync(s.dst).mode & 0o777, 0o400);
  s.sync(29);
  assert.equal(fs.readFileSync(s.dst, 'utf8'), 'line-one\nline-two\nline-three\n');
  s.close();
});

test('a hook that replaces the file (new inode, same size) is detected', (t) => {
  const { src, dir } = setup(t);
  const s = new Snapshot(src, dir);
  s.sync(9);
  fs.rmSync(s.dst);
  fs.writeFileSync(s.dst, 'YYYYYYYY\n');
  assert.equal(s.afterRun(), true);
  assert.equal(fs.readFileSync(s.dst, 'utf8'), 'line-one\n');
  s.close();
});

// Round-4 review (atk2.js): the snapshot was opened with 'w', which follows a symlink a hook planted at its name.
const victimIn = (t) => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'hr-victim-'));
  t.after(() => fs.rmSync(d, { recursive: true, force: true }));
  const v = path.join(d, 'victim');
  fs.writeFileSync(v, 'victim\n');
  fs.chmodSync(v, 0o644);
  return v;
};
const intact = (v) => [fs.readFileSync(v, 'utf8'), fs.statSync(v).mode & 0o777];

test('a symlink planted at the snapshot name is not followed: a new name is used and reported', (t) => {
  const { src, dir } = setup(t);
  const victim = victimIn(t);
  fs.symlinkSync(victim, path.join(dir, 't-0.jsonl'));
  const seen = [];
  const s = new Snapshot(src, dir, 't-0', { onTamper: (kind, name) => seen.push([kind, name]) });
  s.sync(18);
  assert.deepEqual(intact(victim), ['victim\n', 0o644]);
  assert.match(path.basename(s.dst), /^t-0-[0-9a-f]{12}\.jsonl$/);
  assert.equal(fs.readFileSync(s.dst, 'utf8'), 'line-one\nline-two\n');
  assert.deepEqual(seen, [['name_taken', 't-0.jsonl']]);
  s.close();
  assert.equal(fs.lstatSync(path.join(dir, 't-0.jsonl')).isSymbolicLink(), true, 'close does not touch the planted entry');
});

test('a snapshot replaced by a symlink to a victim: the victim is neither read as ours nor written', (t) => {
  const { src, dir } = setup(t);
  const victim = victimIn(t);
  const s = new Snapshot(src, dir);
  s.sync(18);
  const first = s.dst;
  fs.rmSync(first);
  fs.symlinkSync(victim, first);
  assert.equal(s.afterRun(), true);
  assert.notEqual(s.dst, first);
  assert.equal(fs.existsSync(first), false, 'the link is unlinked, not followed');
  s.sync(29);
  s.close();
  assert.deepEqual(intact(victim), ['victim\n', 0o644]);
});

test('recreation never reuses the old name, so a link planted there after the unlink is not followed', (t) => {
  const { src, dir } = setup(t);
  const victim = victimIn(t);
  const s = new Snapshot(src, dir);
  s.sync(9);
  const first = s.dst;
  fs.chmodSync(first, 0o600);
  fs.appendFileSync(first, 'x');
  // Plant the old name as soon as it is gone: wrap unlink, as a racing hook would.
  const unlink = fs.unlinkSync;
  fs.unlinkSync = (p) => { unlink(p); if (p === first) fs.symlinkSync(victim, first); };
  try { s.afterRun(); } finally { fs.unlinkSync = unlink; }
  assert.notEqual(s.dst, first);
  s.sync(29);
  s.close();
  assert.deepEqual(intact(victim), ['victim\n', 0o644]);
});

test('replay: a hook that rewrites the snapshot with same-size bytes does not corrupt later points', async (t) => {
  const { replay } = await import('../src/replay.js');
  const { hookFromFlags } = await import('../src/hooks.js');
  const crypto = await import('node:crypto');
  const here = path.dirname(new URL(import.meta.url).pathname);
  const projectsDir = path.join(here, 'fixtures/projects');
  const A = '-home-fixture-proj/aaaaaaaa-0000-4000-8000-000000000001.jsonl';
  // Print the hash of what we were given, then overwrite it in place with as many x bytes.
  const hook = 'tp=$(sed -n \'s/.*"transcript_path":"\\([^"]*\\)".*/\\1/p\'); sha256sum < "$tp" | cut -d" " -f1; ' +
    'n=$(wc -c < "$tp"); chmod u+w "$tp"; head -c "$n" /dev/zero | tr "\\0" x 1<> "$tp"';
  const res = await replay({ projectsDir, hooks: [hookFromFlags({ hook, event: 'PreToolUse' })], allowNetwork: true, stderr: { write() {} },
    filters: { fileFilter: (f) => f.relPath === A } });
  const buf = fs.readFileSync(path.join(projectsDir, A));
  assert.ok(res.results.length >= 5);
  for (const r of res.results) {
    const want = crypto.createHash('sha256').update(buf.subarray(0, r.snapshotEnd)).digest('hex');
    assert.equal(r.run.stdout.trim(), want, r.key);
  }
});
