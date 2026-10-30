import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { splitLines, readLines, openSourceSync, SourceError } from '../src/lines.js';
import { spawnSync } from 'node:child_process';

const collect = async (gen) => { const out = []; for await (const x of gen) out.push(x); return out; };
const tmpDir = (t) => { const d = fs.mkdtempSync(path.join(os.tmpdir(), 'hr-lines-')); t.after(() => fs.rmSync(d, { recursive: true, force: true })); return d; };

test('splitLines yields offset, length, lineNo and bytes per newline-terminated line', () => {
  const lines = splitLines(Buffer.from('ab\n\ncde\n'));
  assert.deepEqual(lines.map(l => [l.offset, l.length, l.lineNo, l.bytes.toString()]),
    [[0, 2, 1, 'ab'], [3, 0, 2, ''], [4, 3, 3, 'cde']]);
});

test('a last line without a newline is ignored as a partial write', () => {
  const lines = splitLines(Buffer.from('one\ntwo'));
  assert.deepEqual(lines.map(l => l.bytes.toString()), ['one']);
});

test('a line over maxLineBytes has bytes null but keeps its offset and length', () => {
  const lines = splitLines(Buffer.from('short\n0123456789abc\nz\n'), { maxLineBytes: 10 });
  assert.deepEqual(lines.map(l => [l.offset, l.length, l.lineNo, l.bytes && l.bytes.toString()]),
    [[0, 5, 1, 'short'], [6, 13, 2, null], [20, 1, 3, 'z']]);
});

test('readLines over a file matches splitLines across chunk boundaries', async (t) => {
  const d = tmpDir(t);
  const data = Buffer.from('alpha\nbe\n\ngamma-delta\n0123456789012345\nx\npartial');
  const f = path.join(d, 'a.jsonl');
  fs.writeFileSync(f, data);
  for (const chunkSize of [1, 3, 7, 64]) {
    const got = await collect(readLines(f, { maxLineBytes: 12, chunkSize }));
    const want = splitLines(data, { maxLineBytes: 12 });
    assert.deepEqual(got.map(l => [l.offset, l.length, l.lineNo, l.bytes && l.bytes.toString()]),
      want.map(l => [l.offset, l.length, l.lineNo, l.bytes && l.bytes.toString()]), `chunkSize ${chunkSize}`);
  }
});

test('readLines treats the size at open as EOF (bytes appended later are not read)', async (t) => {
  const d = tmpDir(t);
  const f = path.join(d, 'live.jsonl');
  fs.writeFileSync(f, 'one\ntwo\n');
  const it = readLines(f, { chunkSize: 2 });
  const first = await it.next();
  fs.appendFileSync(f, 'three\n');
  const rest = await collect(it);
  assert.deepEqual([first.value, ...rest].map(l => l.bytes.toString()), ['one', 'two']);
});

test('huge lines: a 20 MiB line is over the 16 MiB default cap and a 5 MiB line is under it', async (t) => {
  const d = tmpDir(t);
  const f = path.join(d, 'huge.jsonl');
  const big = Buffer.alloc(20 * 1024 * 1024, 0x61);
  const mid = Buffer.alloc(5 * 1024 * 1024, 0x62);
  fs.writeFileSync(f, Buffer.concat([Buffer.from('{}\n'), big, Buffer.from('\n'), mid, Buffer.from('\n{"a":1}\n')]));
  const got = await collect(readLines(f));
  assert.deepEqual(got.map(l => [l.lineNo, l.offset, l.length, l.bytes === null ? null : l.bytes.length]),
    [[1, 0, 2, 2], [2, 3, big.length, null], [3, 4 + big.length, mid.length, mid.length],
      [4, 5 + big.length + mid.length, 7, 7]]);
});

// Round-6 review: the open alone (O_NONBLOCK) succeeds on a FIFO and on a directory; only the fstat check after it
// refuses them. Removing that check failed no test.
test('openSourceSync refuses a FIFO and a directory with SourceError, and opens a regular file', (t) => {
  const d = tmpDir(t);
  const fifo = path.join(d, 'fifo.jsonl');
  const mk = spawnSync('mkfifo', [fifo]);
  assert.equal(mk.status, 0, String(mk.stderr));
  const dir = path.join(d, 'dir.jsonl');
  fs.mkdirSync(dir);
  for (const p of [fifo, dir]) assert.throws(() => openSourceSync(p), (e) => e instanceof SourceError && /not a regular file/.test(e.message), p);
  const file = path.join(d, 'ok.jsonl');
  fs.writeFileSync(file, 'x\n');
  const fd = openSourceSync(file);
  try { assert.ok(fs.fstatSync(fd).isFile()); } finally { fs.closeSync(fd); }
});
