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
  return { src, dst: path.join(d, 't-0.jsonl') };
};

test('sync appends source bytes up to snapshotEnd, and truncates when a point is released late', (t) => {
  const { src, dst } = setup(t);
  const s = new Snapshot(src, dst);
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

test('a snapshot changed by the hook is recreated from source', (t) => {
  const { src, dst } = setup(t);
  const s = new Snapshot(src, dst);
  s.sync(18);
  if (process.getuid() !== 0) assert.throws(() => fs.writeFileSync(dst, 'tampered'), { code: 'EACCES' });
  fs.chmodSync(dst, 0o600);
  fs.writeFileSync(dst, 'tampered');
  s.afterRun();
  assert.equal(fs.readFileSync(dst, 'utf8'), 'line-one\nline-two\n');
  fs.chmodSync(dst, 0o600);
  fs.appendFileSync(dst, 'extra\n');
  s.afterRun();
  s.sync(29);
  assert.equal(fs.readFileSync(dst, 'utf8'), 'line-one\nline-two\nline-three\n');
  s.close();
});

test('a same-size rewrite by the hook is detected and undone, even with the mtime put back', (t) => {
  const { src, dst } = setup(t);
  const s = new Snapshot(src, dst);
  s.sync(18);
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
  assert.equal(fs.readFileSync(dst, 'utf8'), 'line-one\nline-two\n');
  assert.equal(fs.statSync(dst).mode & 0o777, 0o400);
  s.sync(29);
  assert.equal(fs.readFileSync(dst, 'utf8'), 'line-one\nline-two\nline-three\n');
  s.close();
});

test('a hook that replaces the file (new inode, same size) is detected', (t) => {
  const { src, dst } = setup(t);
  const s = new Snapshot(src, dst);
  s.sync(9);
  fs.rmSync(dst);
  fs.writeFileSync(dst, 'YYYYYYYY\n');
  s.afterRun();
  assert.equal(fs.readFileSync(dst, 'utf8'), 'line-one\n');
  s.close();
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
