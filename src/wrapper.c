#define _GNU_SOURCE
#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/elf.h>
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
#include <time.h>
#include <ucontext.h>
#include <unistd.h>

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

long clone3(struct clone_args *cl_args, size_t size) {
  return syscall(SYS_clone3, cl_args, size);
}

void sighandler(int signo) {
  UNUSED(signo);
  printf("[gdb: pid:%d tid:%d ppid:%d] I got the signal!\n", getpid(), gettid(),
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

char reply[0x1000];

void gdb_send_packet(gdbctx *ctx, char *data) {
  size_t reply_sz = strlen(data) + 0x20;
  assert(reply_sz < sizeof(reply));
  uint8_t c = gdb_checksum(data, strlen(data));
  size_t nbytes = snprintf(reply, reply_sz, "$%s#%c%c", data,
                           chars[(c >> 4) & 0xf], chars[(c >> 0) & 0xf]);
  write(ctx->fd, reply, nbytes);
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
    printf("'%s'\n", buf);
    // assert(0 && "Expected $");
    if (!ctx->stopped) {
      xptrace(PTRACE_INTERRUPT, ctx->ppid, NULL, NULL);
      waitpid(ctx->ppid, &status, 0);
      ctx->stopped = 1;
    }

    printf("termsig: %d\n", WTERMSIG(status));

    ctx->regs->rax = 0;
    ctx->fpregs->cwd = 0;
    xptrace(PTRACE_GETREGS, ctx->ppid, NULL, ctx->regs);
    xptrace(PTRACE_GETFPREGS, ctx->ppid, NULL, ctx->fpregs);
    gdb_send_packet(ctx, "S05"); // sigtrap x86

    return;
  }

  if (starts_with(buf, "qSupported")) {
    gdb_send_packet(ctx, "ReverseStep+;ReverseContinue+");
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
  } else if (starts_with(buf, "q")) {
    buf += strlen("q");

    if (starts_with(buf, "TStatus")) {
      gdb_send_empty(ctx);
    } else if (starts_with(buf, "fThreadInfo")) {
      gdb_send_empty(ctx);
    } else if (starts_with(buf, "L")) {
      gdb_send_empty(ctx);
    } else if (starts_with(buf, "C")) {
      printf("Unimplemented: current thread ID\n");
      gdb_send_packet(ctx, "1");
    } else if (starts_with(buf, "Attached")) {
      gdb_send_packet(ctx, "1");
    } else {
      printf("Unimplemented query: '%s'\n", buf);
      gdb_send_empty(ctx);
    }
  } else if (starts_with(buf, "?")) {
    printf("[gdb] Unimplemented: stop reply ?\n");
    gdb_send_packet(ctx, "S05");
  } else if (starts_with(buf, "g")) {
    printf("[gdb] Unimplemented: get registers\n");

    size_t xsave_size = 560; // x86
    // size_t xsave_size = 528; // x86
    char xsave[560];
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

    memcpy(xsave + 0x00, &regs.rax, sizeof(regs.rax));
    memcpy(xsave + 0x08, &regs.rbx, sizeof(regs.rbx));
    memcpy(xsave + 0x80, &regs.rip, sizeof(regs.rip));

    char data[0x561];

    for (size_t i = 0; i < xsave_size; ++i) {
      data[2 * i] = chars[(xsave[i] >> 4) & 0xf];
      data[2 * i + 1] = chars[(xsave[i] >> 0) & 0xf];
    }

    data[xsave_size * 2] = '\0';
    printf("[gdb] REGISTERS: %s\n", data);

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

    char data[0x200];
    assert(sz * 2 < sizeof(data));

    for (size_t i = 0; i < sz; ++i) {
      data[2 * i] = chars[(addr[i] >> 4) & 0xf];
      data[2 * i + 1] = chars[(addr[i] >> 0) & 0xf];
    }
    data[sz * 2] = '\0';

    printf("[gdb] MEMORY: %p[%ld]: %s\n", addr, sz, data);

    gdb_send_packet(ctx, data);
  } else if (starts_with(buf, "bc")) {
    printf("[gdb] reverse continue!\n");

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

    printf("[gdb] Checking out to %.16lx\n",
           pbvt_head()->parent->current->hash);
    pbvt_checkout(pbvt_head()->parent);

    printf("[gdb] SETREGS: %p\n", ctx->regs);

    // HACK: We shouldn't need this
    // xptrace(PTRACE_INTERRUPT, ctx->ppid, NULL, NULL);
    // printf("Waiting for child...\n");
    // waitpid(ctx->ppid, &status, 0);
    // ctx->stopped = 1;

    for (int i = 0; i < 0x10; ++i) {
      ptrace(PTRACE_SETREGS, ctx->ppid, NULL, ctx->regs);
      ptrace(PTRACE_SETFPREGS, ctx->ppid, NULL, ctx->fpregs);
      printf("Set rip to %p\n", ctx->regs->rip);
    }
    gdb_send_packet(ctx, "S05"); // sigtrap x86
  } else if (starts_with(buf, "vCont?")) {
    gdb_send_packet(ctx, "vCont;c;s");
  } else if (starts_with(buf, "vCont;")) {
    printf("Assuming continue... %d\n", ctx->ppid);

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
    xptrace(PTRACE_CONT, ctx->ppid, NULL, NULL);
    ctx->stopped = 0;
  } else if (starts_with(buf, "s")) {
    printf("single-step!");
    int status;
    xptrace(PTRACE_SINGLESTEP, ctx->ppid, NULL, NULL);
    waitpid(ctx->ppid, &status, 0);
    ctx->stopped = 1;
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
      printf("[heap] %s %lx-%lx\n", flags, from, to);
      pbvt_track_range((void *)from, to - from);
      continue;
    }

    if (strcmp(name, "[stack]") == 0) {
      printf("[stack] %s %lx-%lx\n", flags, from, to);
      pbvt_track_range((void *)from, to - from);
      continue;
    }

    // replace userfaultfd with PROT_READ|sigsegv
    // if (strstr(name, "test-app") != NULL) {
    //   printf("[test-app] %s %lx-%lx %s\n", flags, from, to, name);
    //   pbvt_track_range((void *)from, to - from);
    //   continue;
    // }

    printf("[ignore] %s %lx-%lx %s\n", flags, from, to, name);
  }
  close(maps);

  printf("Done tracking memory...\n");

  pbvt_commit();
  pbvt_branch_commit("main");

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
  gdb_addr.sin_port = htons(4444);
  printf("socket: %d\n", gdb_socket);
  if (bind(gdb_socket, (struct sockaddr *)&gdb_addr, sizeof(gdb_addr)) < 0) {
    close(gdb_socket);
    xperror("bind");
  }

  if (listen(gdb_socket, 10) < 0)
    xperror("listen");

  printf("Waiting for connection from gdb on 0.0.0.0:4444...");
  int cfd = accept(gdb_socket, NULL, NULL);
  if (cfd < 0)
    xperror("accept");

  printf("done.\n");

  gdbctx gctx = {0};
  gctx.fd = cfd;
  gctx.ppid = ppid;
  gctx.stopped = 1;

  gctx.regs = pbvt_calloc(1, sizeof(struct user_regs_struct));
  gctx.fpregs = pbvt_calloc(1, sizeof(struct user_fpregs_struct));

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

  for (;;) {
    if (poll(pollfds, 2, -1) < 0)
      xperror("poll(wrapper)");

    // Timer
    if (pollfds[0].revents & POLLERR)
      xperror("POLLERR in timer");
    if (pollfds[0].revents & POLLIN) {
      uint64_t expiry;
      read(pollfds[0].fd, &expiry, sizeof(expiry));
      printf("expiry: %d\n", expiry);
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
      printf("[gdb] \"%s\"\n", gdb_buf);
      gdb_handle_packet(&gctx, gdb_buf, nbytes);

      continue;
    }

    printf("Got poll but not handled!");
  }

  for (int i = 0;; ++i) {
    usleep(100);

    xptrace(PTRACE_INTERRUPT, ppid, NULL, NULL);
    waitpid(ppid, &status, 0);

    // Cause page fault on our regs, since ptrace will not correctly trigger
    // our uffd_monitor.
    gctx.regs->rax = 0;
    gctx.fpregs->cwd = 0;
    xptrace(PTRACE_GETREGS, ppid, NULL, gctx.regs);
    xptrace(PTRACE_GETFPREGS, ppid, NULL, gctx.fpregs);

    Commit *c = pbvt_commit();
    if (i % 1000 == 0) {
      printf("[gdb: pid: %d] State: %.16lx\n", getpid(), c->current->hash);
      // pbvt_stats();
    }
    if (pbvt_size() > 999)
      pbvt_gc_n(800);
    xptrace(PTRACE_CONT, ppid, NULL, NULL);
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
