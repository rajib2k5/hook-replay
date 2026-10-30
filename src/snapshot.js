// One growing temp copy of a transcript (DESIGN.md §5 "Snapshot"): always the exact source bytes [0, end).
// Bytes are copied, never re-serialised.
import fs from 'node:fs';

const COPY_CHUNK = 1024 * 1024;

export class Snapshot {
  constructor(srcPath, dstPath) {
    this.src = srcPath;
    this.dst = dstPath;
    this.srcFd = fs.openSync(srcPath, 'r');
    this.#open();
    this.written = 0;
    this.#mark();
  }

  // Our writes go through the fd, so the file can stay 0400: a hook that wants to change it must chmod first.
  #open() {
    this.fd = fs.openSync(this.dst, 'w', 0o600);
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

  // The hook may have changed the file (any write, chmod, utimes, or a replacement): recreate it from source
  // unless inode, size and ctime are exactly what we left.
  afterRun() {
    let st = null;
    try { st = fs.statSync(this.dst, { bigint: true }); } catch { /* deleted by the hook */ }
    if (st && st.ino === this.seen.ino && st.size === this.seen.size && st.ctimeNs === this.seen.ctime) return;
    try { fs.closeSync(this.fd); } catch { /* ignore */ }
    try { fs.rmSync(this.dst, { force: true }); } catch { /* ignore */ }
    this.#open();
    const end = this.written;
    this.written = 0;
    this.sync(end);
  }

  close() {
    try { fs.closeSync(this.fd); } catch { /* ignore */ }
    try { fs.closeSync(this.srcFd); } catch { /* ignore */ }
    fs.rmSync(this.dst, { force: true });
  }
}
