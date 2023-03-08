#include <assert.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>

#include "gdbstub.h"
#include "pbvt.h"

#define MIN(a, b) ((a) < (b) ? (a) : (b))

static char *chars = "0123456789abcdef";

char reply[0x4800];

int starts_with(char *str, char *prefix) {
  return strncmp(prefix, str, strlen(prefix)) == 0;
}

void gdb_pause(gdbctx *ctx) {
  int status;
  xptrace(PTRACE_INTERRUPT, ctx->ppid, NULL, NULL);
  waitpid(ctx->ppid, &status, 0);
  ctx->stopped = 1;
}

void gdb_continue(gdbctx *ctx) {
  xptrace(PTRACE_SYSCALL, ctx->ppid, NULL, NULL);
  ctx->stopped = 0;
}

void gdb_save_state(gdbctx *ctx) {
  // ctx->sketch is saved automatically :)
  ctx->regs->rax = 0;
  ctx->fpregs->cwd = 0;
  xptrace(PTRACE_GETREGS, ctx->ppid, NULL, ctx->regs);
  xptrace(PTRACE_GETFPREGS, ctx->ppid, NULL, ctx->fpregs);
  pbvt_commit();
}

uint8_t gdb_checksum(char *c, size_t n) {
  uint8_t r = 0;
  for (size_t i = 0; i < n; ++i)
    r += c[i];
  return r;
}

void gdb_send_empty(gdbctx *ctx) { gdb_send_packet(ctx, ""); }

void gdb_send_packet(gdbctx *ctx, char *data) {
  size_t reply_sz = strlen(data) + 0x20;
  assert(reply_sz < sizeof(reply));
  uint8_t c = gdb_checksum(data, strlen(data));
  size_t nbytes = snprintf(reply, reply_sz, "$%s#%c%c", data,
                           chars[(c >> 4) & 0xf], chars[(c >> 0) & 0xf]);
  write(ctx->fd, reply, nbytes);
}

// TODO: Escape packet bytes
void gdb_send_packet_bytes(gdbctx *ctx, char *data, size_t n) {
  uint8_t c = 0;
  size_t t = 0;
  reply[t++] = '$';
  for (size_t i = 0; i < n; ++i) {
    switch (data[i]) {
    case '$':
    case '#':
    case '}':
    case '*':
      reply[t++] = '}';
      reply[t++] = data[i] ^ 0x20;
      c += (data[i] ^ 0x20) + '}';
      break;
    default:
      reply[t++] = data[i];
      c += data[i];
      break;
    }
  }
  reply[t++] = '#';
  reply[t++] = chars[(c >> 4) & 0xf];
  reply[t++] = chars[(c >> 0) & 0xf];
  write(ctx->fd, reply, t);
}

void gdb_handle_packet(gdbctx *ctx, char *buf, size_t n) {
  char *endptr = buf + n;
  if (*buf == '\x03') {
    if (!ctx->stopped)
      gdb_pause(ctx);

    gdb_save_state(ctx);
    write(ctx->fd, "+", 1);
    gdb_send_packet(ctx, "S05"); // sigtrap x86
    buf += 1;
    n -= 1;
  }

  if (buf == endptr)
    return;

  if (*buf == '+')
    buf += 1;

  if (buf == endptr)
    return;

  // TODO: This should be a proper ack, not just whenever we think it'll pacify
  // GDB
  write(ctx->fd, "+", 1);

  assert(*buf == '$');
  if (*buf == '$')
    buf++;

  char c = buf[0];
  buf++;
  n--;
  switch (c) {
  case '!':
    return gdb_send_packet(ctx, "OK");
  case '?':
    GDB_PRINTF("PARTIAL: stop reply ?\n", 0);
    return gdb_send_packet(ctx, "S05");
  case 'b':
    return gdb_handle_b_commands(ctx, buf, n);
  case 'c':
    return gdb_handle_c_commands(ctx, buf, n);
  case 'D':
    return gdb_handle_d_set_commands(ctx, buf, n);
  case 'g':
    return gdb_handle_g_commands(ctx, buf, n);
  case 'H':
    return gdb_handle_h_set_commands(ctx, buf, n);
  case 'm':
    return gdb_handle_m_commands(ctx, buf, n);
  case 'M':
    return gdb_handle_m_set_commands(ctx, buf, n);
  case 'P':
    return gdb_handle_p_set_commands(ctx, buf, n);
  case 'q':
    return gdb_handle_q_commands(ctx, buf, n);
  case 's':
    return gdb_handle_s_commands(ctx, buf, n);
  case 'v':
    return gdb_handle_v_commands(ctx, buf, n);
  case 'C':
  case 'k':
  case 'F':
  case 'G':
  case 'p':
  case 'Z':
  case 'z':
  case 'T':
  case 'Q':
  default:
    GDB_PRINTF("Unandled %s\n", buf);
    gdb_send_empty(ctx);
    break;
  }
}

// Handle backwards commands
void gdb_handle_b_commands(gdbctx *ctx, char *buf, size_t n) {
  UNUSED(n);

  switch (buf[0]) {
  case 'c': {
    if (!ctx->stopped)
      gdb_pause(ctx);

    GDB_PRINTF("Checking out to %.16lx\n", pbvt_head()->parent->current->hash);
    pbvt_checkout(pbvt_head()->parent);

    ptrace(PTRACE_SETREGS, ctx->ppid, NULL, ctx->regs);
    ptrace(PTRACE_SETFPREGS, ctx->ppid, NULL, ctx->fpregs);
    gdb_send_packet(ctx, "S05"); // sigtrap x86
    break;
  }
  case 's': {
    if (!ctx->stopped) {
      gdb_pause(ctx);
      gdb_save_state(ctx);
    }

    pbvt_checkout(pbvt_commit_parent(pbvt_head()));
    ptrace(PTRACE_SETREGS, ctx->ppid, NULL, ctx->regs);
    ptrace(PTRACE_SETFPREGS, ctx->ppid, NULL, ctx->fpregs);
    gdb_send_packet(ctx, "S05"); // sigtrap x86
    break;
  }
  }
}

void gdb_handle_c_commands(gdbctx *ctx, char *buf, size_t n) {
  UNUSED(buf);
  UNUSED(n);

  gdb_save_state(ctx);
  gdb_continue(ctx);
  // gdb_send_packet(ctx, "S12"); // sigcont x86
  gdb_send_packet(ctx, "OK");
}

void gdb_handle_d_set_commands(gdbctx *ctx, char *buf, size_t n) {
  UNUSED(buf);
  UNUSED(n);

  GDB_PRINTF("Received detach, goodbye!\n", 0);
  xptrace(PTRACE_DETACH, ctx->ppid, NULL, NULL);
  exit(-1);
}

void gdb_handle_g_commands(gdbctx *ctx, char *buf, size_t n) {
  UNUSED(buf);
  UNUSED(n);

  GDB_PRINTF("PARTIAL: get registers\n", 0);

  size_t xsave_size = 300; // x86_64
  char xsave[xsave_size];
  for (size_t i = 0; i < xsave_size; ++i)
    xsave[i] = i;

  if (!ctx->stopped)
    gdb_pause(ctx);

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
}

// TODO: Set thread for current operations
void gdb_handle_h_set_commands(gdbctx *ctx, char *buf, size_t n) {
  UNUSED(n);

  if (starts_with(buf, "g")) {
    gdb_send_packet(ctx, "OK");
  } else if (starts_with(buf, "c")) {
    gdb_send_packet(ctx, "OK");
  } else {
    assert(0 && "unknown");
  }
}

void gdb_handle_m_commands(gdbctx *ctx, char *buf, size_t n) {
  char *endptr = buf + n;
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
  // GDB_PRINTF("MEMORY: %p[%ld]: %s\n", addr, sz, data);

  gdb_send_packet(ctx, data);
}

void gdb_handle_m_set_commands(gdbctx *ctx, char *buf, size_t n) {
  char *endptr = buf + n;
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
}

void gdb_handle_p_set_commands(gdbctx *ctx, char *buf, size_t n) {
  char *endptr = buf + n;

  if (!ctx->stopped)
    gdb_pause(ctx);

  gdb_save_state(ctx);
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
}

void gdb_handle_q_commands(gdbctx *ctx, char *buf, size_t n) {
  char *endptr = buf + n;

  if (starts_with(buf, "Supported")) {
    gdb_send_packet(ctx, "PacketSize=47ff;ReverseStep+;ReverseContinue+;qXfer:"
                         "exec-file:read+;qXfer:features:read+;qXfer:libraries-"
                         "svr4:read+;qXfer:auxv:read+;swbreak-");
  } else if (starts_with(buf, "TStatus")) {
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

    char data[0x400];
    size_t t = 0;
    data[t++] = 'l';
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "/proc/%d/auxv", ctx->ppid);
    int afd = open(path, O_RDONLY);
    t += pread(afd, &data[t], length, offset);
    close(afd);

    gdb_send_packet_bytes(ctx, data, t);
  } else if (starts_with(buf, "Xfer:libraries-svr4:read:")) {
    gdb_send_packet(ctx, "l<library-list-svr4 version=\"1.0\"/>");
  } else if (starts_with(buf, "Xfer:features:read:target.xml:")) {
    buf += strlen("Xfer:features:read:target.xml:");

    uintptr_t offset = strtoull(buf, &endptr, 0x10);
    buf = endptr;
    assert(*buf == ',');
    buf += 1;
    uintptr_t count = strtoull(buf, &endptr, 0x10);

    int tfd = open("target.xml", O_RDONLY);

    char data[0x4000];
    data[0] = 'm';
    ssize_t nbytes = pread(tfd, data + 1, MIN(count, sizeof(data) - 1), offset);
    close(tfd);

    if (nbytes == 0) {
      gdb_send_packet(ctx, "l");
    } else if (nbytes < 0) {
      char res[0x20];
      snprintf(res, sizeof(res), "E%lx", nbytes);
      gdb_send_packet(ctx, res);
    } else {
      gdb_send_packet_bytes(ctx, data, nbytes + 1);
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
}

void gdb_handle_s_commands(gdbctx *ctx, char *buf, size_t n) {
  UNUSED(buf);
  UNUSED(n);
  int status;

  if (!ctx->stopped)
    gdb_pause(ctx);
  xptrace(PTRACE_SINGLESTEP, ctx->ppid, NULL, NULL);
  waitpid(ctx->ppid, &status, 0);
  gdb_send_packet(ctx, "S05");
}

void gdb_handle_v_commands(gdbctx *ctx, char *buf, size_t n) {
  UNUSED(n);

  if (starts_with(buf, "MustReplyEmpty")) {
    gdb_send_empty(ctx);
  } else if (starts_with(buf, "File")) {
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

      char data[0x4000];
      ssize_t nbytes = pread(fildes, data, MIN(count, sizeof(data)), offset);
      GDB_PRINTF("pread(%lx, %lx, %lx) => %lx\n", fildes, count, offset,
                 nbytes);
      if (nbytes < 0) {
        char res[0x20];
        snprintf(res, sizeof(res), "E%lx", nbytes);
        gdb_send_packet(ctx, res);
      } else {
        char data[0x5000];
        size_t t = snprintf(data, sizeof(data), "F%lx;", nbytes);
        gdb_send_packet_bytes(ctx, data, t);
      }
    } else if (starts_with(buf, "fstat:")) {
      buf += strlen("fstat:");
      // char *endptr;
      // size_t fildes = strtoull(buf, &endptr, 0x10);

      char data[0x40] = {0};
      uint64_t val = 0x030201;
      memcpy(data + 28, &val, sizeof(val));
      size_t nbytes = sizeof(data);
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
  } else if (starts_with(buf, "Cont?")) {
    gdb_send_packet(ctx, "vCont;c;s");
  } else if (starts_with(buf, "Cont")) {
    GDB_PRINTF("Assuming continue... %d\n", ctx->ppid);

    gdb_save_state(ctx);
    gdb_continue(ctx);

    // TODO: Is this correct?
    // gdb_send_empty(ctx);
  }
}
