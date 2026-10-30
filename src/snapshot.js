// One growing temp copy of a transcript (DESIGN.md §5 "Snapshot"): always the exact source bytes [0, end).
// Bytes are copied, never re-serialised.
import fs from 'node:fs';

const COPY_CHUNK = 1024 * 1024;

export class Snapshot {
  constructor(srcPath, dstPath) {
    this.src = srcPath;
    this.dst = dstPath;
    this.srcFd = fs.openSync(srcPath, 'r');
    this.fd = fs.openSync(dstPath, 'w', 0o600);
    fs.fchmodSync(this.fd, 0o600);
    this.written = 0;
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
  }

  // The hook may have changed the file; restore it if its size differs from what we wrote.
  afterRun() {
    let size = -1;
    try { size = fs.statSync(this.dst).size; } catch { /* deleted by the hook */ }
    if (size === this.written) return;
    try { fs.closeSync(this.fd); } catch { /* ignore */ }
    try { fs.rmSync(this.dst, { force: true }); } catch { /* ignore */ }
    this.fd = fs.openSync(this.dst, 'w', 0o600);
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
