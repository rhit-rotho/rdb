#define _GNU_SOURCE
#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/sched.h>
#include <netinet/in.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/user.h>
#include <sys/wait.h>

#include "pbvt.h"

#define STACK_SIZE (8 * 1024 * 1024)
#define PROCMAPS_LINE_MAX_LENGTH (PATH_MAX + 100)
#define UNUSED(x) (void)(x)

#define xperror(x)                                                             \
  do {                                                                         \
    perror(x);                                                                 \
    exit(-1);                                                                  \
  } while (0);

#define xptrace(req, pid, addr, data)                                          \
  do {                                                                         \
    if (ptrace(req, pid, addr, data) == -1) {                                  \
      xperror(#req);                                                           \
    }                                                                          \
  } while (0)

#ifndef __cpuid_count
#define __cpuid_count(level, count, a, b, c, d)                                \
  __asm__ __volatile__("cpuid\n\t"                                             \
                       : "=a"(a), "=b"(b), "=c"(c), "=d"(d)                    \
                       : "0"(level), "2"(count))
#endif

static char *chars = "0123456789abcdef";

#define GDB_PRINTF_HEADER "\e[33m[gdb: %d]\e[0m "
#define GDB_PRINTF_TRAILER ""

#define GDB_PRINTF(fmt, ...)                                                   \
  do {                                                                         \
    if (1)                                                                     \
      fprintf(stderr, GDB_PRINTF_HEADER fmt GDB_PRINTF_TRAILER, getpid(),      \
              __VA_ARGS__);                                                    \
  } while (0)

#define MIN(a, b) ((a) < (b) ? (a) : (b))

long clone3(struct clone_args *cl_args, size_t size) {
  return syscall(SYS_clone3, cl_args, size);
}

void sighandler(int signo) {
  UNUSED(signo);
  GDB_PRINTF("pid:%d tid:%d ppid:%d I got the signal!\n", getpid(), gettid(),
             getppid());
  exit(-1);
}

int read_line(int fd, char *buf, size_t n) {
  size_t nbytes = 0;
  while (nbytes < n && read(fd, buf, 1)) {
    if (buf[0] == '\n') {
      *buf = '\0';
      return 1;
    }
    buf++;
    nbytes++;
  }
  return 0;
}

int starts_with(char *str, char *prefix) {
  return strncmp(prefix, str, strlen(prefix)) == 0;
}

typedef struct gdbctx {
  int fd;
  pid_t ppid;
  volatile struct user_regs_struct *regs;
  volatile struct user_fpregs_struct *fpregs;
  int stopped;
} gdbctx;

void gdb_send_packet(gdbctx *ctx, char *data);
void gdb_send_empty(gdbctx *ctx);

uint8_t gdb_checksum(char *c, size_t n) {
  uint8_t r = 0;
  for (size_t i = 0; i < n; ++i)
    r += c[i];
  return r;
}

void gdb_send_empty(gdbctx *ctx) { gdb_send_packet(ctx, ""); }

char reply[0x4800];

void gdb_send_packet(gdbctx *ctx, char *data) {
  size_t reply_sz = strlen(data) + 0x20;
  assert(reply_sz < sizeof(reply));
  uint8_t c = gdb_checksum(data, strlen(data));
  size_t nbytes = snprintf(reply, reply_sz, "$%s#%c%c", data,
                           chars[(c >> 4) & 0xf], chars[(c >> 0) & 0xf]);
  write(ctx->fd, reply, nbytes);
}

void gdb_send_packet_bytes(gdbctx *ctx, char *data, size_t n) {
  uint8_t c = gdb_checksum(data, n);
  size_t t = 0;
  reply[t++] = '$';
  for (size_t i = 0; i < n; ++i)
    reply[t++] = data[i];
  reply[t++] = '#';
  reply[t++] = chars[(c >> 4) & 0xf];
  reply[t++] = chars[(c >> 0) & 0xf];
  write(ctx->fd, reply, t);
}

void gdb_handle_packet(gdbctx *ctx, char *buf, size_t n) {
  char *endptr = buf + n;

  // 66 gdb_num_core_regs

  // int ack = 0;
  if (*buf == '+') {
    // ack = 1;
    buf++;
  }

  if (buf == endptr)
    return;

  // if (*buf == '-') {
  //   ack = -1;
  //   buf++;
  // }

  write(ctx->fd, "+", 1);

  if (*buf == '$') {
    buf++;
  } else {
    int status;
    GDB_PRINTF("'%s'\n", buf);
    // assert(0 && "Expected $");
    if (!ctx->stopped) {
      xptrace(PTRACE_INTERRUPT, ctx->ppid, NULL, NULL);
      waitpid(ctx->ppid, &status, 0);
      ctx->stopped = 1;
    }

    GDB_PRINTF("termsig: %d\n", WTERMSIG(status));

    ctx->regs->rax = 0;
    ctx->fpregs->cwd = 0;
    xptrace(PTRACE_GETREGS, ctx->ppid, NULL, ctx->regs);
    xptrace(PTRACE_GETFPREGS, ctx->ppid, NULL, ctx->fpregs);
    gdb_send_packet(ctx, "S05"); // sigtrap x86

    return;
  }

  if (starts_with(buf, "qSupported")) {
    gdb_send_packet(ctx, "PacketSize=47ff;ReverseStep+;ReverseContinue+;qXfer:"
                         "exec-file:read+;qXfer:features:read+;qXfer:libraries-"
                         "svr4:read+;qXfer:auxv:read+;swbreak-");
  } else if (starts_with(buf, "vMustReplyEmpty")) {
    buf += strlen("vMustReplyEmpty");

    gdb_send_empty(ctx);
  } else if (starts_with(buf, "H")) {
    buf += strlen("H");

    if (starts_with(buf, "g")) {
      gdb_send_packet(ctx, "OK");
    } else if (starts_with(buf, "c")) {
      gdb_send_packet(ctx, "OK");
    } else {
      assert(0 && "unknown");
    }
  } else if (starts_with(buf, "D")) {
    GDB_PRINTF("Received detach, goodbye!\n", 0);
    kill(ctx->ppid, SIGINT);
    exit(-1);
  } else if (starts_with(buf, "q")) {
    buf += strlen("q");

    if (starts_with(buf, "TStatus")) {
      gdb_send_empty(ctx);
    } else if (starts_with(buf, "Offsets")) {
      gdb_send_empty(ctx);
    } else if (starts_with(buf, "fThreadInfo")) {
      // TODO: gdb expects several comma separated lists of thread ids, with a
      // single 'l' response when there are none remaining
      char pid[0x10];
      snprintf(pid, sizeof(pid), "m%x", ctx->ppid);
      gdb_send_packet(ctx, pid);
    } else if (starts_with(buf, "sThreadInfo")) {
      gdb_send_packet(ctx, "l");
    } else if (starts_with(buf, "ThreadExtraInfo")) {
      // TODO: get thread-id
      gdb_send_empty(ctx);
    } else if (starts_with(buf, "L")) {
      gdb_send_empty(ctx);
    } else if (starts_with(buf, "C")) {
      char pid[0x10];
      snprintf(pid, sizeof(pid), "p%x.-1", ctx->ppid);
      gdb_send_packet(ctx, pid);
    } else if (starts_with(buf, "Attached")) {
      gdb_send_packet(ctx, "1");
    } else if (starts_with(buf, "Symbol::")) {
      gdb_send_packet(ctx, "OK");
    } else if (starts_with(buf, "Xfer:auxv:read::")) {
      buf += strlen("Xfer:auxv:read::");

      uintptr_t offset = strtoull(buf, &endptr, 0x10);
      buf = endptr;
      assert(*buf == ',');
      buf += 1;
      uintptr_t length = strtoull(buf, &endptr, 0x10);

      GDB_PRINTF("AUXV[%d, %d]\n", offset, length);

      char ebuf[0x400];
      size_t t = 0;
      ebuf[t++] = 'l';
      char path[PATH_MAX];
      snprintf(path, sizeof(path), "/proc/%d/auxv", ctx->ppid);
      int afd = open(path, O_RDONLY);
      t += pread(afd, &ebuf[t], length, offset);
      close(afd);

      // TODO: Properly escape binary afd
      gdb_send_packet_bytes(ctx, ebuf, t);
    } else if (starts_with(buf, "Xfer:libraries-svr4:read:")) {
      gdb_send_packet(ctx, "l<library-list-svr4 version=\"1.0\"/>");
    } else if (starts_with(buf, "Xfer:features:read:target.xml:")) {
      buf += strlen("Xfer:features:read:target.xml:");

      uintptr_t offset = strtoull(buf, &endptr, 0x10);
      buf = endptr;
      assert(*buf == ',');
      buf += 1;
      uintptr_t count = strtoull(buf, &endptr, 0x10);

      GDB_PRINTF("[gdb] target.xml[%d..%d]\n", offset, offset + count);

      int tfd = open("target.xml", O_RDONLY);

      char ebuf[0x4000];
      ssize_t nbytes = pread(tfd, ebuf, MIN(count, sizeof(ebuf)), offset);
      close(tfd);

      if (nbytes == 0) {
        gdb_send_packet(ctx, "l");
      } else if (nbytes < 0) {
        char res[0x20];
        snprintf(res, sizeof(res), "E%lx", nbytes);
        gdb_send_packet(ctx, res);
      } else {
        char data[0x5000];
        size_t t = snprintf(data, sizeof(data), "m");
        for (ssize_t i = 0; i < nbytes; ++i) {
          switch (ebuf[i]) {
          case '$':
          case '#':
          case '}':
          case '*':
            data[t++] = '}';
            data[t++] = ebuf[i] ^ 0x20;
            break;
          default:
            data[t++] = ebuf[i];
            break;
          }
        }
        gdb_send_packet_bytes(ctx, data, t);
      }
    } else if (starts_with(buf, "Xfer:exec-file:read:")) {
      buf += strlen("Xfer:exec-file:read:");

      // size_t annex = 0;
      buf += 1;
      uintptr_t offset = strtoull(buf, &endptr, 0x10);
      buf = endptr;
      assert(*buf == ',');
      buf += 1;
      uintptr_t length = strtoull(buf, &endptr, 0x10);

      GDB_PRINTF("PARTIAL read-file: %d %d\n", offset, length);

      // uint8_t ebuf[0x200];
      size_t nbytes = 0;

      if (nbytes == 0) {
        gdb_send_packet(ctx, "l/home/omar/projects/rdb/test-app");
        return;
      }

      // TODO: Implement
      // gdb_send_packet_bytes(ctx, data, t);
    } else {
      GDB_PRINTF("Unimplemented query: '%s'\n", buf);
      gdb_send_empty(ctx);
    }
  } else if (starts_with(buf, "?")) {
    GDB_PRINTF("PARTIAL: stop reply ?\n", 0);
    gdb_send_packet(ctx, "S05");
  } else if (starts_with(buf, "P")) {
    buf += strlen("P");

    int status;
    if (!ctx->stopped) {
      xptrace(PTRACE_INTERRUPT, ctx->ppid, NULL, NULL);
      waitpid(ctx->ppid, &status, 0);
      ctx->stopped = 1;
    }

    ctx->regs->rax = 0;
    ctx->fpregs->cwd = 0;
    xptrace(PTRACE_GETREGS, ctx->ppid, NULL, ctx->regs);
    xptrace(PTRACE_GETFPREGS, ctx->ppid, NULL, ctx->fpregs);

    size_t regid = strtoull(buf, &endptr, 0x10);

    buf = endptr;
    assert(*buf == '=');
    buf += 1;
    uintptr_t val = strtoull(buf, &endptr, 0x10);
    val = __bswap_64(val);

    GDB_PRINTF("Setting register %ld to %p\n", regid, val);
    // HACK: This is dumb, use target.xml to map register ids to offsets
    switch (regid) {
    case 0:
      ctx->regs->rax = val;
      break;
    case 1:
      ctx->regs->rbx = val;
      break;
    case 2:
      ctx->regs->rcx = val;
      break;
    case 3:
      ctx->regs->rdx = val;
      break;
    case 4:
      ctx->regs->rsi = val;
      break;
    case 5:
      ctx->regs->rdi = val;
      break;
    case 6:
      ctx->regs->rbp = val;
      break;
    case 7:
      ctx->regs->rsp = val;
      break;
    case 8:
      ctx->regs->r8 = val;
      break;
    case 9:
      ctx->regs->r9 = val;
      break;
    case 10:
      ctx->regs->r10 = val;
      break;
    case 11:
      ctx->regs->r11 = val;
      break;
    case 12:
      ctx->regs->r12 = val;
      break;
    case 13:
      ctx->regs->r13 = val;
      break;
    case 14:
      ctx->regs->r14 = val;
      break;
    case 15:
      ctx->regs->r15 = val;
      break;
    case 16:
      ctx->regs->rip = val;
      break;
    case 17:
      ctx->regs->eflags = val;
      break;
    default:
      GDB_PRINTF("UNIMPLEMENTED: set register %d\n", regid);
      break;
    }
    xptrace(PTRACE_SETREGS, ctx->ppid, NULL, ctx->regs);
    xptrace(PTRACE_SETFPREGS, ctx->ppid, NULL, ctx->fpregs);

    gdb_send_packet(ctx, "OK");
  } else if (starts_with(buf, "g")) {
    GDB_PRINTF("PARTIAL: get registers\n", 0);

    size_t xsave_size = 300; // x86-64
    // size_t xsave_size = 528; // x86
    char xsave[xsave_size];
    for (size_t i = 0; i < xsave_size; ++i)
      xsave[i] = i;

    int status;
    if (!ctx->stopped) {
      xptrace(PTRACE_INTERRUPT, ctx->ppid, NULL, NULL);
      waitpid(ctx->ppid, &status, 0);
      ctx->stopped = 1;
    }

    struct user_regs_struct regs;
    xptrace(PTRACE_GETREGS, ctx->ppid, NULL, &regs);

    // HACK: This is dumb, we should be using the target.xml spec
    memcpy(xsave + 0x00, &regs.rax, sizeof(regs.rax));
    memcpy(xsave + 0x08, &regs.rbx, sizeof(regs.rbx));
    memcpy(xsave + 0x10, &regs.rcx, sizeof(regs.rcx));
    memcpy(xsave + 0x18, &regs.rdx, sizeof(regs.rdx));
    memcpy(xsave + 0x20, &regs.rsi, sizeof(regs.rsi));
    memcpy(xsave + 0x28, &regs.rdi, sizeof(regs.rdi));
    memcpy(xsave + 0x30, &regs.rbp, sizeof(regs.rbp));
    memcpy(xsave + 0x38, &regs.rsp, sizeof(regs.rsp));
    memcpy(xsave + 0x40, &regs.r8, sizeof(regs.r8));
    memcpy(xsave + 0x48, &regs.r9, sizeof(regs.r9));
    memcpy(xsave + 0x50, &regs.r10, sizeof(regs.r10));
    memcpy(xsave + 0x58, &regs.r11, sizeof(regs.r11));
    memcpy(xsave + 0x60, &regs.r12, sizeof(regs.r12));
    memcpy(xsave + 0x68, &regs.r13, sizeof(regs.r13));
    memcpy(xsave + 0x70, &regs.r14, sizeof(regs.r14));
    memcpy(xsave + 0x78, &regs.r15, sizeof(regs.r15));
    memcpy(xsave + 0x80, &regs.rip, sizeof(regs.rip));
    memcpy(xsave + 0x88, &regs.eflags, sizeof(regs.eflags));
    memcpy(xsave + 0x8c, &regs.cs, sizeof(regs.cs));
    memcpy(xsave + 0x90, &regs.ss, sizeof(regs.ss));
    memcpy(xsave + 0x94, &regs.ds, sizeof(regs.ds));
    memcpy(xsave + 0x98, &regs.es, sizeof(regs.es));
    memcpy(xsave + 0x9c, &regs.fs, sizeof(regs.fs));
    memcpy(xsave + 0xa0, &regs.gs, sizeof(regs.gs));

    // floating point registers...

    memcpy(xsave + 0x114, &regs.orig_rax, sizeof(regs.orig_rax));
    memcpy(xsave + 0x11c, &regs.fs_base, sizeof(regs.fs_base));
    memcpy(xsave + 0x124, &regs.gs_base, sizeof(regs.gs_base));

    char data[2 * xsave_size + 1];

    for (size_t i = 0; i < xsave_size; ++i) {
      data[2 * i] = chars[(xsave[i] >> 4) & 0xf];
      data[2 * i + 1] = chars[(xsave[i] >> 0) & 0xf];
    }

    data[xsave_size * 2] = '\0';
    GDB_PRINTF("REGISTERS: %s\n", data);

    gdb_send_packet(ctx, data);
  } else if (starts_with(buf, "m")) {
    buf += strlen("m");
    char *addr = (char *)strtoull(buf, &endptr, 0x10);

    if (addr == NULL) {
      gdb_send_packet(ctx, "E14");
      return;
    }

    buf = endptr;
    assert(*buf == ',');
    buf += 1;
    size_t sz = strtoull(buf, &endptr, 0x10);

    char data[0x900];
    assert(sz * 2 < sizeof(data));

    uint64_t words[0x200];
    size_t m = 0;
    for (size_t t = 0; t < sz; t += sizeof(uint64_t)) {
      uint64_t word = ptrace(PTRACE_PEEKDATA, ctx->ppid, addr + t, NULL);
      if (word == UINT64_MAX) {
        gdb_send_packet(ctx, "E14");
        return;
      }
      words[m++] = word;
    }

    uint8_t *p = (uint8_t *)words;
    for (size_t i = 0; i < sz; ++i) {
      data[2 * i] = chars[(p[i] >> 4) & 0xf];
      data[2 * i + 1] = chars[(p[i] >> 0) & 0xf];
    }
    for (size_t i = 0; i < sz; ++i)
      if (p[i] != (uint8_t)addr[i])
        GDB_PRINTF("p[%d] = %x != addr[%d] = %x\n", i, p[i], i, addr[i]);

    data[sz * 2] = '\0';
    GDB_PRINTF("MEMORY: %p[%ld]: %s\n", addr, sz, data);

    gdb_send_packet(ctx, data);
  } else if (starts_with(buf, "M")) {
    buf += strlen("M");
    char *addr = (char *)strtoull(buf, &endptr, 0x10);

    if (addr == NULL) {
      gdb_send_packet(ctx, "E14");
      return;
    }

    buf = endptr;
    assert(*buf == ',');
    buf += 1;
    size_t sz = strtoull(buf, &endptr, 0x10);
    buf = endptr;
    assert(*buf == ':');
    buf += 1;

    uint8_t data[0x100];
    size_t x = 0;
    for (size_t i = 0; i < sz * 2; i += 2)
      sscanf(&buf[i], "%2hhx", &data[x++]);

    GDB_PRINTF("WRITE MEM: %p %lx\n", addr, sz);

    // TODO: Support software breakpoints
    if (data[0] == 0xcc) {
      gdb_send_packet(ctx, "E14");
      return;
    }

    // TODO: Swap to PTRACE_POKEDATA and masking
    for (size_t i = 0; i < sz; ++i)
      addr[i] = data[i];

    gdb_send_packet(ctx, "OK");
  } else if (starts_with(buf, "bs")) {
    GDB_PRINTF("reverse step!\n", 0);
    GDB_PRINTF("stopped: %d\n", ctx->stopped);

    int status;
    if (!ctx->stopped) {
      xptrace(PTRACE_INTERRUPT, ctx->ppid, NULL, NULL);
      waitpid(ctx->ppid, &status, 0);
      ctx->stopped = 1;

      pbvt_commit();
    }

    GDB_PRINTF("Current state: %.16lx\n", pbvt_head()->current);
    GDB_PRINTF("Current parent: %.16lx\n", pbvt_head()->parent);

    pbvt_checkout(pbvt_commit_parent(pbvt_head()));
    GDB_PRINTF("SETREGS: %p\n", ctx->regs);
    ptrace(PTRACE_SETREGS, ctx->ppid, NULL, ctx->regs);
    ptrace(PTRACE_SETFPREGS, ctx->ppid, NULL, ctx->fpregs);
    GDB_PRINTF("Set rip to %p\n", ctx->regs->rip);
    gdb_send_packet(ctx, "S05"); // sigtrap x86
  } else if (starts_with(buf, "bc")) {
    GDB_PRINTF("reverse continue!\n", 0);

    int status;
    if (!ctx->stopped) {
      xptrace(PTRACE_INTERRUPT, ctx->ppid, NULL, NULL);
      waitpid(ctx->ppid, &status, 0);
      ctx->stopped = 1;
    }

    // ctx->regs->rax = 0;
    // ctx->fpregs->cwd = 0;
    // xptrace(PTRACE_GETREGS, ctx->ppid, NULL, ctx->regs);
    // xptrace(PTRACE_GETFPREGS, ctx->ppid, NULL, ctx->fpregs);

    GDB_PRINTF("Checking out to %.16lx\n", pbvt_head()->parent->current->hash);
    pbvt_checkout(pbvt_head()->parent);

    GDB_PRINTF("SETREGS: %p\n", ctx->regs);

    // HACK: We shouldn't need this
    // xptrace(PTRACE_INTERRUPT, ctx->ppid, NULL, NULL);
    // GDB_PRINTF("Waiting for child...\n");
    // waitpid(ctx->ppid, &status, 0);
    // ctx->stopped = 1;

    for (int i = 0; i < 0x10; ++i) {
      ptrace(PTRACE_SETREGS, ctx->ppid, NULL, ctx->regs);
      ptrace(PTRACE_SETFPREGS, ctx->ppid, NULL, ctx->fpregs);
    }
    gdb_send_packet(ctx, "S05"); // sigtrap x86
  } else if (starts_with(buf, "vFile:")) {
    buf += strlen("vFile:");
    if (starts_with(buf, "setfs:")) {
      gdb_send_packet(ctx, "F0");
    } else if (starts_with(buf, "open:")) {
      buf += strlen("open:");
      char *path_hex = strtok(buf, ",");
      int flags = atoi(strtok(NULL, ","));
      int mode = atoi(strtok(NULL, ","));

      char path[PATH_MAX];
      size_t x = 0;
      for (size_t i = 0; i < strlen(path_hex); i += 2)
        sscanf(&path_hex[i], "%2hhx", &path[x++]);
      path[x] = '\0';
      int ret = open(path, flags, mode);
      GDB_PRINTF("open: '%s' %d %d %d\n", path, flags, mode, ret);
      char res[0x10];
      if (ret < 0) {
        snprintf(res, sizeof(res), "E%x", ret);
        gdb_send_packet(ctx, res);
      } else {
        snprintf(res, sizeof(res), "F%x", ret);
        gdb_send_packet(ctx, res);
      }
    } else if (starts_with(buf, "pread:")) {
      buf += strlen("pread:");

      char *endptr;
      size_t fildes = strtoull(buf, &endptr, 0x10);
      buf = endptr + 1;
      size_t count = strtoull(buf, &endptr, 0x10);
      buf = endptr + 1;
      size_t offset = strtoull(buf, &endptr, 0x10);
      buf = endptr;

      char ebuf[0x4000];
      ssize_t nbytes = pread(fildes, ebuf, MIN(count, sizeof(ebuf)), offset);
      GDB_PRINTF("pread(%lx, %lx, %lx) => %lx\n", fildes, count, offset,
                 nbytes);
      if (nbytes < 0) {
        char res[0x20];
        snprintf(res, sizeof(res), "E%lx", nbytes);
        gdb_send_packet(ctx, res);
      } else {
        char data[0x5000];
        size_t t = snprintf(data, sizeof(data), "F%lx;", nbytes);
        for (ssize_t i = 0; i < nbytes; ++i) {
          switch (ebuf[i]) {
          case '$':
          case '#':
          case '}':
          case '*':
            data[t++] = '}';
            data[t++] = ebuf[i] ^ 0x20;
            break;
          default:
            data[t++] = ebuf[i];
            break;
          }
        }
        gdb_send_packet_bytes(ctx, data, t);
      }
    } else if (starts_with(buf, "fstat:")) {
      buf += strlen("fstat:");
      // char *endptr;
      // size_t fildes = strtoull(buf, &endptr, 0x10);

      char ebuf[0x40] = {0};
      uint64_t val = 0x030201;
      memcpy(ebuf + 28, &val, sizeof(val));
      size_t nbytes = sizeof(ebuf);
      // int ret = fstat(fildes, &buf);
      int ret = 0;
      // size_t nbytes = 9999;
      if (ret < 0) {
        char res[0x20];
        // TODO: Add errno
        snprintf(res, sizeof(res), "E%x", 11);
        gdb_send_packet(ctx, res);
      } else {
        char data[0x500];
        size_t t = snprintf(data, sizeof(data), "F%lx;", nbytes);
        for (size_t i = 0; i < nbytes; ++i) {
          switch (ebuf[i]) {
          case '#':
          case '$':
          case '*':
          case '}':
            data[t++] = '}';
            data[t++] = ebuf[i] ^ 0x20;
            break;
          default:
            data[t++] = ebuf[i];
            break;
          }
        }
        GDB_PRINTF("fstat: '%s' %d\n", data, t);
        gdb_send_packet_bytes(ctx, data, t);
      }
    } else if (starts_with(buf, "close:")) {
      buf += strlen("close:");

      char *endptr;
      size_t fildes = strtoull(buf, &endptr, 0x10);
      buf = endptr + 1;

      int ret = close(fildes);
      char res[0x20];
      if (ret < 0) {
        snprintf(res, sizeof(res), "E%x", ret);
        gdb_send_packet(ctx, res);
      } else {
        snprintf(res, sizeof(res), "F%x", ret);
        gdb_send_packet(ctx, res);
      }
    } else {
      gdb_send_empty(ctx);
    }
  } else if (starts_with(buf, "vCont?")) {
    gdb_send_packet(ctx, "vCont;c;s");
  } else if (starts_with(buf, "vCont;")) {
    GDB_PRINTF("Assuming continue... %d\n", ctx->ppid);

    ctx->regs->rax = 0;
    ctx->fpregs->cwd = 0;
    xptrace(PTRACE_GETREGS, ctx->ppid, NULL, ctx->regs);
    xptrace(PTRACE_GETFPREGS, ctx->ppid, NULL, ctx->fpregs);

    xptrace(PTRACE_CONT, ctx->ppid, NULL, NULL);
    ctx->stopped = 0;

    // TODO: Is this correct?
    // gdb_send_empty(ctx);
  } else if (starts_with(buf, "c")) {
    ctx->regs->rax = 0;
    ctx->fpregs->cwd = 0;
    xptrace(PTRACE_GETREGS, ctx->ppid, NULL, ctx->regs);
    xptrace(PTRACE_GETFPREGS, ctx->ppid, NULL, ctx->fpregs);
    pbvt_commit();

    xptrace(PTRACE_CONT, ctx->ppid, NULL, NULL);
    ctx->stopped = 0;
  } else if (starts_with(buf, "s")) {
    GDB_PRINTF("single-step %d\n", ctx->stopped);

    int status;
    xptrace(PTRACE_SINGLESTEP, ctx->ppid, NULL, NULL);
    waitpid(ctx->ppid, &status, 0);
    ctx->stopped = 1;

    GDB_PRINTF("%d\n", __LINE__);
    ctx->regs->rax = 0;
    ctx->fpregs->cwd = 0;
    xptrace(PTRACE_GETREGS, ctx->ppid, NULL, ctx->regs);
    xptrace(PTRACE_GETFPREGS, ctx->ppid, NULL, ctx->fpregs);
    pbvt_commit();

    gdb_send_packet(ctx, "S05");
  } else {
    gdb_send_empty(ctx);
  }
}

void *gdbstub_stk;
pid_t ppid;

int gdbstub(void *args) {
  UNUSED(args);

  int status;

  // Immediately sezie and interrupt process, this is so we can easily
  // interrupt the process later.
  xptrace(PTRACE_SEIZE, ppid, NULL, NULL);
  xptrace(PTRACE_INTERRUPT, ppid, NULL, NULL);

  waitpid(ppid, &status, 0);

  setbuf(stdout, NULL);
  setbuf(stderr, NULL);

  pbvt_init();

  char path[PATH_MAX];
  snprintf(path, PATH_MAX, "/proc/%d/maps", ppid);
  int maps = open(path, O_RDONLY);
  if (maps < 0)
    xperror("fopen");

  char buf[PROCMAPS_LINE_MAX_LENGTH];
  while (read_line(maps, buf, PROCMAPS_LINE_MAX_LENGTH)) {
    char flags[5] = {0};
    char name[PATH_MAX] = {0};
    uint64_t from, to, inode;
    uint32_t major, minor, offset;
    sscanf(buf, "%lx-%lx %4c %x %x:%x %ld %[^\n]", &from, &to, flags, &offset,
           &major, &minor, &inode, name);

    // bool is_r = flags[0] == 'r';
    bool is_w = flags[1] == 'w';
    // bool is_x = flags[2] == 'x';

    if (!is_w)
      continue;

    if (strstr(name, "libwrapper.so") != NULL)
      continue;
    if (strstr(name, "libpbvt.so") != NULL)
      continue;

    if (strcmp(name, "[heap]") == 0) {
      GDB_PRINTF("[heap] %s %lx-%lx\n", flags, from, to);
      pbvt_track_range((void *)from, to - from);
      continue;
    }

    if (strcmp(name, "[stack]") == 0) {
      GDB_PRINTF("[stack] %s %lx-%lx\n", flags, from, to);
      pbvt_track_range((void *)from, to - from);
      continue;
    }

    // replace userfaultfd with PROT_READ|sigsegv
    // if (strstr(name, "test-app") != NULL) {
    //   GDB_PRINTF("[test-app] %s %lx-%lx %s\n", flags, from, to, name);
    //   pbvt_track_range((void *)from, to - from);
    //   continue;
    // }

    GDB_PRINTF("[ignore] %s %lx-%lx %s\n", flags, from, to, name);
  }
  close(maps);

  GDB_PRINTF("Done tracking memory...\n", 0);

  pbvt_commit();
  pbvt_branch_commit("main");

  gdbctx gctx = {0};
  // gctx.fd = cfd;
  gctx.ppid = ppid;
  gctx.stopped = 1;
  gctx.regs = pbvt_calloc(1, sizeof(struct user_regs_struct));
  gctx.fpregs = pbvt_calloc(1, sizeof(struct user_fpregs_struct));

  pbvt_commit();

  int gdb_socket = socket(AF_INET, SOCK_STREAM, 0);
  if (gdb_socket < 0)
    xperror("socket");

  const int enable = 1;
  if (setsockopt(gdb_socket, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) <
      0)
    xperror("setsockopt(SO_REUSEADDR)");

  struct sockaddr_in gdb_addr = {0};
  gdb_addr.sin_family = AF_INET;
  gdb_addr.sin_addr.s_addr = INADDR_ANY;
  int port = 4445;
  gdb_addr.sin_port = htons(port);
  GDB_PRINTF("socket: %d\n", gdb_socket);
  if (bind(gdb_socket, (struct sockaddr *)&gdb_addr, sizeof(gdb_addr)) < 0) {
    close(gdb_socket);
    xperror("bind");
  }

  if (listen(gdb_socket, 10) < 0)
    xperror("listen");

  GDB_PRINTF("Waiting for connection from gdb on 0.0.0.0:%d...", port);
  int cfd = accept(gdb_socket, NULL, NULL);
  if (cfd < 0)
    xperror("accept");
  gctx.fd = cfd;

  GDB_PRINTF("done.\n", 0);

  int timer = timerfd_create(CLOCK_MONOTONIC, 0);
  struct itimerspec arm = {0};
  arm.it_interval.tv_nsec = 0;
  arm.it_interval.tv_sec = 1;
  if (timerfd_settime(timer, 0, &arm, NULL) < 0)
    xperror("timerfd_settime");

  // TODO: Add signalfd for handling segfaults, syscalls, and signals
  struct pollfd pollfds[2] = {0};
  pollfds[0].fd = timer;
  pollfds[1].events = POLLIN | POLLERR;
  pollfds[1].fd = cfd;
  pollfds[1].events = POLLIN | POLLERR;

  char gdb_buf[0x100];

  gctx.regs->rax = 0;
  gctx.fpregs->cwd = 0;
  xptrace(PTRACE_GETREGS, gctx.ppid, NULL, gctx.regs);
  xptrace(PTRACE_GETFPREGS, gctx.ppid, NULL, gctx.fpregs);
  pbvt_commit();

  // xptrace(PTRACE_SINGLESTEP, gctx.ppid, NULL, NULL);

  for (;;) {
    if (poll(pollfds, 2, -1) < 0)
      xperror("poll(wrapper)");

    // Timer
    if (pollfds[0].revents & POLLERR)
      xperror("POLLERR in timer");
    if (pollfds[0].revents & POLLIN) {
      uint64_t expiry;
      read(pollfds[0].fd, &expiry, sizeof(expiry));
      GDB_PRINTF("expiry: %d\n", expiry);
      continue;
    }

    // socket
    if (pollfds[1].revents & POLLERR)
      xperror("POLLERR in socket");
    if (pollfds[1].revents & POLLIN) {
      int nbytes = read(pollfds[1].fd, gdb_buf, sizeof(gdb_buf) - 1);
      if (nbytes < 0)
        xperror("read");
      if (nbytes == 0)
        break;
      gdb_buf[nbytes] = '\0';
      GDB_PRINTF("Remote: \"%s\"\n", gdb_buf);
      gdb_handle_packet(&gctx, gdb_buf, nbytes);

      continue;
    }

    GDB_PRINTF("Got poll but not handled!", 0);
  }

  return 0;
}

__attribute__((constructor)) static void wrapper_init(void) {
  gdbstub_stk = mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE,
                     MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  ppid = getpid();
  clone(gdbstub, gdbstub_stk + STACK_SIZE, CLONE_VM, NULL);
}

__attribute__((destructor)) static void wrapper_fini(void) {
  if (munmap(gdbstub_stk, STACK_SIZE) == -1)
    xperror("munmap");
}
