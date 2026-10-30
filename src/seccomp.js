// Classic-BPF seccomp program for `bwrap --seccomp <fd>` (DESIGN.md §5): socket() fails with EACCES for every
// address family, so a hook can reach neither the network nor a filesystem Unix socket (docker, D-Bus, ...).
// socketpair() stays allowed: it makes no connection. io_uring_setup() fails with ENOSYS, because
// IORING_OP_SOCKET would create a socket without the socket() syscall. A syscall from any other ABI (32-bit
// compat) kills the process. Numbers are from <asm-generic/unistd.h> (aarch64) and libseccomp (x86_64).

// <linux/bpf_common.h>
const BPF_LD_W_ABS = 0x00 | 0x00 | 0x20;
const BPF_JMP_JEQ_K = 0x05 | 0x10 | 0x00;
const BPF_JMP_JGE_K = 0x05 | 0x30 | 0x00;
const BPF_RET_K = 0x06 | 0x00;
// <linux/seccomp.h>
const RET_KILL_PROCESS = 0x80000000;
const RET_ERRNO = 0x00050000;
const RET_ALLOW = 0x7fff0000;
const EACCES = 13;
const ENOSYS = 38;
// offsetof(struct seccomp_data, ...)
const OFF_NR = 0;
const OFF_ARCH = 4;
const X32_SYSCALL_BIT = 0x40000000;

export const ARCHES = {
  arm64: { audit: 0xC00000B7, socket: 198, ioUringSetup: 425, x32: false },
  x64: { audit: 0xC000003E, socket: 41, ioUringSetup: 425, x32: true },
};

const ins = (code, jt, jf, k) => ({ code, jt, jf, k: k >>> 0 });

// Returns [{code, jt, jf, k}], or null when the architecture is not supported (no isolation then).
export function program(arch = process.arch) {
  const a = ARCHES[arch];
  if (!a) return null;
  const p = [
    ins(BPF_LD_W_ABS, 0, 0, OFF_ARCH),
    ins(BPF_JMP_JEQ_K, 1, 0, a.audit),
    ins(BPF_RET_K, 0, 0, RET_KILL_PROCESS),
    ins(BPF_LD_W_ABS, 0, 0, OFF_NR),
  ];
  if (a.x32) p.push(ins(BPF_JMP_JGE_K, 0, 1, X32_SYSCALL_BIT), ins(BPF_RET_K, 0, 0, RET_ERRNO | EACCES));
  p.push(
    ins(BPF_JMP_JEQ_K, 0, 1, a.socket), ins(BPF_RET_K, 0, 0, RET_ERRNO | EACCES),
    ins(BPF_JMP_JEQ_K, 0, 1, a.ioUringSetup), ins(BPF_RET_K, 0, 0, RET_ERRNO | ENOSYS),
    ins(BPF_RET_K, 0, 0, RET_ALLOW),
  );
  return p;
}

// struct sock_filter[] in host byte order (both supported arches are little-endian), as bwrap reads it.
export function encode(prog) {
  const buf = Buffer.alloc(prog.length * 8);
  prog.forEach((x, i) => {
    buf.writeUInt16LE(x.code, i * 8);
    buf.writeUInt8(x.jt, i * 8 + 2);
    buf.writeUInt8(x.jf, i * 8 + 3);
    buf.writeUInt32LE(x.k, i * 8 + 4);
  });
  return buf;
}
