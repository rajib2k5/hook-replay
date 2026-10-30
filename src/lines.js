// Split a transcript into newline-terminated lines by bytes (not readline: lines can be several MB, and we
// need exact byte offsets for snapshots). A last line without '\n' is a partial write and is ignored.
import fs from 'node:fs';

export const DEFAULT_MAX_LINE_BYTES = 16 * 1024 * 1024;

// A transcript source is opened without blocking and without following a last-component link, and must be a regular
// file: a hook can replace a transcript not yet read with a FIFO, whose blocking open would stall hook-replay for good,
// signal handlers included (round-5 review, fifo.sh). Failing that, a SourceError: the file is counted unreadable.
const { O_RDONLY, O_NONBLOCK, O_NOFOLLOW } = fs.constants;
export const SOURCE_FLAGS = O_RDONLY | O_NONBLOCK | O_NOFOLLOW;
export class SourceError extends Error {}
const notRegular = (file) => new SourceError(`${file} is not a regular file`);

export function openSourceSync(file) {
  let fd;
  try { fd = fs.openSync(file, SOURCE_FLAGS); } catch (e) { throw new SourceError(`${file}: ${e.code ?? e.message}`); }
  if (fs.fstatSync(fd).isFile()) return fd;
  fs.closeSync(fd);
  throw notRegular(file);
}

// In-memory form, used by tests and small inputs. Each line: {offset, length, lineNo, bytes|null}; length
// excludes the '\n'. bytes is null when length > maxLineBytes.
export function splitLines(buf, { maxLineBytes = DEFAULT_MAX_LINE_BYTES } = {}) {
  const out = [];
  let start = 0;
  let lineNo = 0;
  for (;;) {
    const nl = buf.indexOf(0x0a, start);
    if (nl === -1) break;
    const length = nl - start;
    out.push({ offset: start, length, lineNo: ++lineNo, bytes: length > maxLineBytes ? null : buf.subarray(start, nl) });
    start = nl + 1;
  }
  return out;
}

// Streaming form over a file. The size at open is EOF: live transcripts grow while we read them.
export async function* readLines(file, { maxLineBytes = DEFAULT_MAX_LINE_BYTES, chunkSize = 1024 * 1024 } = {}) {
  let fh;
  try { fh = await fs.promises.open(file, SOURCE_FLAGS); } catch (e) { throw new SourceError(`${file}: ${e.code ?? e.message}`); }
  try {
    const st = await fh.stat();
    if (!st.isFile()) throw notRegular(file);
    const { size } = st;
    const chunk = Buffer.alloc(Math.max(1, Math.min(chunkSize, size || 1)));
    let pos = 0;
    let lineNo = 0;
    let lineStart = 0;
    let parts = [];
    let partLen = 0;
    let oversize = false;
    while (pos < size) {
      const { bytesRead } = await fh.read(chunk, 0, Math.min(chunk.length, size - pos), pos);
      if (bytesRead === 0) break;
      let i = 0;
      while (i < bytesRead) {
        const nl = chunk.indexOf(0x0a, i);
        const end = nl === -1 || nl >= bytesRead ? bytesRead : nl;
        const n = end - i;
        if (!oversize) {
          if (partLen + n > maxLineBytes) { oversize = true; parts = []; } else if (n > 0) parts.push(Buffer.from(chunk.subarray(i, end)));
        }
        partLen += n;
        if (end === bytesRead) { i = bytesRead; break; }
        yield { offset: lineStart, length: partLen, lineNo: ++lineNo, bytes: oversize ? null : Buffer.concat(parts, partLen) };
        lineStart += partLen + 1;
        parts = [];
        partLen = 0;
        oversize = false;
        i = end + 1;
      }
      pos += bytesRead;
    }
  } finally {
    await fh.close();
  }
}
