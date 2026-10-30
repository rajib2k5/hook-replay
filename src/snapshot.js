// One growing temp copy of a transcript (DESIGN.md §5 "Snapshot"): always the exact source bytes [0, end).
// Bytes are copied, never re-serialised.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { openSourceSync } from './lines.js';

const COPY_CHUNK = 1024 * 1024;
const { O_WRONLY, O_CREAT, O_EXCL, O_NOFOLLOW } = fs.constants;
// Every file hook-replay creates in the temp root: a new entry or nothing. O_EXCL fails on any existing entry, a
// planted symlink included, so the open never follows a link a hook left there (round-4 review, atk2.js).
export const CREATE_FLAGS = O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW;

// Creates `<base><ext>` in dir, or `<base>-<random><ext>` when that name is taken or `unique` is set. Returns
// {fd, path, taken}, where taken is the name that was already there (or null).
const rand = () => crypto.randomBytes(6).toString('hex');
export function createExclusive(dir, base, ext = '', { unique = false } = {}) {
  let name = unique ? `${base}-${rand()}${ext}` : base + ext;
  let taken = null;
  for (let i = 0; ; i++) {
    const p = path.join(dir, name);
    try { return { fd: fs.openSync(p, CREATE_FLAGS, 0o600), path: p, taken }; } catch (e) {
      if (e.code !== 'EEXIST' || i >= 8) throw e;
      taken ??= name;
      name = `${base}-${rand()}${ext}`;
    }
  }
}

// `onTamper(kind, name)` is told when the first name was taken ('name_taken') or when the hook changed the file
// ('changed'); either way a new name is used and nothing at the old one is opened.
export class Snapshot {
  constructor(srcPath, dir, base = 't-0', { onTamper = () => {} } = {}) {
    this.src = srcPath;
    this.dir = dir;
    this.base = base;
    this.onTamper = onTamper;
    this.srcFd = openSourceSync(srcPath);
    this.#open();
    this.written = 0;
    this.#mark();
  }

  // Our writes go through the fd, so the file can stay 0400: a hook that wants to change it must chmod first.
  // A recreation always takes a new random name, never the one just unlinked (a hook could race to plant it).
  #open(unique = false) {
    const { fd, path: p, taken } = createExclusive(this.dir, this.base, '.jsonl', { unique });
    if (taken) this.onTamper('name_taken', taken);
    this.fd = fd;
    this.dst = p;
    fs.fchmodSync(this.fd, 0o400);
  }

  // Identity of the bytes we wrote. ctime changes on every write, chmod or utimes and cannot be set back.
  #mark() {
    const st = fs.fstatSync(this.fd, { bigint: true });
    this.seen = { ino: st.ino, size: st.size, ctime: st.ctimeNs };
  }

  #copy(from, to) {
    const buf = Buffer.alloc(Math.min(COPY_CHUNK, Math.max(1, to - from)));
    let pos = from;
    while (pos < to) {
      const n = fs.readSync(this.srcFd, buf, 0, Math.min(buf.length, to - pos), pos);
      if (n === 0) throw new Error(`source ${this.src} shorter than expected`);
      fs.writeSync(this.fd, buf, 0, n, pos);
      pos += n;
    }
  }

  sync(end) {
    if (end > this.written) this.#copy(this.written, end);
    else if (end < this.written) fs.ftruncateSync(this.fd, end);
    this.written = end;
    this.#mark();
  }

  // The hook may have changed the file (any write, chmod, utimes, or a replacement, a symlink included): recreate
  // it from source under a new name unless the entry is the inode we left, with its size and ctime. lstat, so a
  // link is judged as a link. The old name is unlinked (unlink removes a link, never its target).
  // Returns true when the snapshot had been changed.
  afterRun() {
    let st = null;
    try { st = fs.lstatSync(this.dst, { bigint: true }); } catch { /* deleted by the hook */ }
    if (st && st.isFile() && st.ino === this.seen.ino && st.size === this.seen.size && st.ctimeNs === this.seen.ctime) return false;
    this.onTamper('changed', path.basename(this.dst));
    try { fs.closeSync(this.fd); } catch { /* ignore */ }
    try { fs.unlinkSync(this.dst); } catch { /* gone, or a directory: teardown removes it */ }
    this.#open(true);
    const end = this.written;
    this.written = 0;
    this.sync(end);
    return true;
  }

  close() {
    try { fs.closeSync(this.fd); } catch { /* ignore */ }
    try { fs.closeSync(this.srcFd); } catch { /* ignore */ }
    try { fs.unlinkSync(this.dst); } catch { /* ignore */ }
  }
}
