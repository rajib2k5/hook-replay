// One growing temp copy of a transcript (DESIGN.md §5 "Snapshot"): always the exact source bytes [0, end).
// Bytes are copied, never re-serialised.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { openSourceSync } from './lines.js';

const COPY_CHUNK = 1024 * 1024;
const { O_RDONLY, O_WRONLY, O_CREAT, O_EXCL, O_NOFOLLOW, O_DIRECTORY } = fs.constants;
// Every file hook-replay creates in the temp root: a new entry or nothing. O_EXCL fails on any existing entry, a
// planted symlink included, so the open never follows a link a hook left there (round-4 review, atk2.js).
export const CREATE_FLAGS = O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW;

export class SnapDirError extends Error {}

// The snapshot dir, opened once. O_NOFOLLOW covers only the last component: a hook that renamed the temp root (or
// the dir) and put a link at the old path made the next create land in the link's target (round-5 review, ren.sh,
// snapln.sh). So every entry is created, checked and removed through /proc/self/fd/<fd>/<name>, which names this
// dir wherever it now is, and before each create the path must still name it (same dev and ino), or SnapDirError.
// Without /proc (not Linux, --allow-network only) the path is used, after the same check.
export class SnapDir {
  constructor(dir) {
    this.path = dir;
    this.fd = fs.openSync(dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    const st = fs.fstatSync(this.fd, { bigint: true });
    this.id = { dev: st.dev, ino: st.ino };
    this.via = fs.existsSync(`/proc/self/fd/${this.fd}`) ? `/proc/self/fd/${this.fd}` : dir;
  }

  at(name) { return path.join(this.via, name); }

  verify() {
    let st = null;
    try { st = fs.lstatSync(this.path, { bigint: true }); } catch { /* gone */ }
    if (!st || !st.isDirectory() || st.dev !== this.id.dev || st.ino !== this.id.ino) {
      throw new SnapDirError(`${this.path} is no longer the snapshot directory hook-replay created (a hook renamed or replaced it or a parent); stopped rather than create a snapshot elsewhere`);
    }
  }

  close() { try { fs.closeSync(this.fd); } catch { /* ignore */ } }
}

// Creates `<base><ext>` in dir (a SnapDir), or `<base>-<random><ext>` when that name is taken or `unique` is set.
// Returns {fd, name, path, taken}: path is the name under dir.path (what a hook is given), taken the name that was
// already there (or null).
const rand = () => crypto.randomBytes(6).toString('hex');
export function createExclusive(dir, base, ext = '', { unique = false } = {}) {
  let name = unique ? `${base}-${rand()}${ext}` : base + ext;
  let taken = null;
  for (let i = 0; ; i++) {
    dir.verify();
    try { return { fd: fs.openSync(dir.at(name), CREATE_FLAGS, 0o600), name, path: path.join(dir.path, name), taken }; } catch (e) {
      if (e.code !== 'EEXIST' || i >= 8) throw e;
      taken ??= name;
      name = `${base}-${rand()}${ext}`;
    }
  }
}

// `onTamper(kind, name)` is told when the first name was taken ('name_taken') or when the hook changed the file
// ('changed'); either way a new name is used and nothing at the old one is opened.
export class Snapshot {
  // dir is a SnapDir (shared, closed by its owner) or a path (opened here, closed by close()).
  constructor(srcPath, dir, base = 't-0', { onTamper = () => {} } = {}) {
    this.src = srcPath;
    this.ownDir = !(dir instanceof SnapDir);
    this.base = base;
    this.onTamper = onTamper;
    this.srcFd = openSourceSync(srcPath);
    try {
      this.dir = this.ownDir ? new SnapDir(dir) : dir;
      this.#open();
    } catch (e) {
      fs.closeSync(this.srcFd);
      if (this.ownDir) this.dir?.close();
      throw e;
    }
    this.written = 0;
    this.#mark();
  }

  // Our writes go through the fd, so the file can stay 0400: a hook that wants to change it must chmod first.
  // A recreation always takes a new random name, never the one just unlinked (a hook could race to plant it).
  #open(unique = false) {
    const { fd, name, path: p, taken } = createExclusive(this.dir, this.base, '.jsonl', { unique });
    if (taken) this.onTamper('name_taken', taken);
    this.fd = fd;
    this.name = name;
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
    try { st = fs.lstatSync(this.dir.at(this.name), { bigint: true }); } catch { /* deleted by the hook */ }
    if (st && st.isFile() && st.ino === this.seen.ino && st.size === this.seen.size && st.ctimeNs === this.seen.ctime) return false;
    this.onTamper('changed', this.name);
    try { fs.closeSync(this.fd); } catch { /* ignore */ }
    this.fd = null; // #open can throw; close() must not close a reused fd number
    try { fs.unlinkSync(this.dir.at(this.name)); } catch { /* gone, or a directory: teardown removes it */ }
    this.#open(true);
    const end = this.written;
    this.written = 0;
    this.sync(end);
    return true;
  }

  // Idempotent: teardown on a signal closes the snapshots still open.
  close() {
    if (this.closed) return;
    this.closed = true;
    try { fs.closeSync(this.fd); } catch { /* ignore */ }
    try { fs.closeSync(this.srcFd); } catch { /* ignore */ }
    try { fs.unlinkSync(this.dir.at(this.name)); } catch { /* ignore */ }
    if (this.ownDir) this.dir.close();
  }
}
