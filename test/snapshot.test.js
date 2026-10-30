import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
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
  assert.equal(fs.statSync(dst).mode & 0o777, 0o600);
  s.close();
  assert.equal(fs.existsSync(dst), false);
});

test('a snapshot changed by the hook is recreated from source', (t) => {
  const { src, dst } = setup(t);
  const s = new Snapshot(src, dst);
  s.sync(18);
  fs.writeFileSync(dst, 'tampered');
  s.afterRun();
  assert.equal(fs.readFileSync(dst, 'utf8'), 'line-one\nline-two\n');
  fs.appendFileSync(dst, 'extra\n');
  s.afterRun();
  s.sync(29);
  assert.equal(fs.readFileSync(dst, 'utf8'), 'line-one\nline-two\nline-three\n');
  s.close();
});
