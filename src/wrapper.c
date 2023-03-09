#define _GNU_SOURCE
#include <arpa/inet.h>
#include <assert.h>
#include <capstone/capstone.h>
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
#include <sys/timerfd.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include "gdbstub.h"
#include "pbvt.h"
#include "pt.h"

// TODO: Grab binary when first injecting into process
#define APP_NAME "test-app"

#define STACK_SIZE (8 * 1024 * 1024)
#define PROCMAPS_LINE_MAX_LENGTH (PATH_MAX + 100)

// Saturate X at +/-DERIVE_MAX
#define DERIVE_MAX (0xfefefefe)
#define SAT_INC(x)                                                             \
  do {                                                                         \
    if ((x) + 1 < DERIVE_MAX)                                                  \
      x++;                                                                     \
  } while (0)

void *gdbstub_stk;
pid_t ppid;
int fildes[2];

void sighandler(int signo) {
  UNUSED(signo);
  GDB_PRINTF("pid:%d tid:%d ppid:%d I got the signal!\n", getpid(), gettid(),
             getppid());
  kill(ppid, SIGINT);
  exit(0);
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

int gdbstub(void *args) {
  UNUSED(args);

  int status;

  // Immediately sezie and interrupt process, this is so we can easily
  // interrupt the process later.
  xptrace(PTRACE_SEIZE, ppid, NULL, NULL);
  xptrace(PTRACE_INTERRUPT, ppid, NULL, NULL);
  char c = 1;
  write(fildes[1], &c, 1);

  waitpid(ppid, &status, 0);

  setbuf(stdout, NULL);
  setbuf(stderr, NULL);

  pbvt_init();

  signal(SIGSEGV, sighandler);

  // GDB_PRINTF("Press [enter] to continue...\n", 0);
  // char t;
  // read(0, &t, 1);

  char path[PATH_MAX];
  snprintf(path, PATH_MAX, "/proc/%d/maps", ppid);
  int maps = open(path, O_RDONLY);
  if (maps < 0)
    xperror("fopen");

  struct pt_image_section_cache *pim = pt_iscache_alloc(NULL);
  int asid;

  char buf[PROCMAPS_LINE_MAX_LENGTH];
  uint64_t image_start;
  while (read_line(maps, buf, PROCMAPS_LINE_MAX_LENGTH)) {
    char flags[5] = {0};
    char name[PATH_MAX] = {0};
    uint64_t from, to, inode;
    uint32_t major, minor, offset;
    sscanf(buf, "%lx-%lx %4c %x %x:%x %ld %[^\n]", &from, &to, flags, &offset,
           &major, &minor, &inode, name);

    bool is_r = flags[0] == 'r';
    bool is_w = flags[1] == 'w';
    bool is_x = flags[2] == 'x';

    int prot = PROT_NONE;
    prot |= is_r ? PROT_READ : PROT_NONE;
    prot |= is_w ? PROT_WRITE : PROT_NONE;
    prot |= is_x ? PROT_EXEC : PROT_NONE;

    if (strstr(name, APP_NAME) && image_start == 0) {
      image_start = from;
      GDB_PRINTF("Image base: %.16lx\n", image_start);
    }

    // PT decoder add range
    if (is_x && strstr(name, APP_NAME)) {
      GDB_PRINTF("(offset: %.6lx) %s %lx-%lx '%s'\n", from - image_start, flags,
                 from, to, name);
      asid =
          pt_iscache_add_file(pim, name, from - image_start, to - from, from);
      if (asid < 0)
        GDB_PRINTF("pt_image_add_file failed!\n", 0);
    }

    if (!is_w)
      continue;

    if (strstr(name, "libwrapper.so") != NULL)
      continue;
    if (strstr(name, "libpbvt.so") != NULL)
      continue;

    // if (strcmp(name, "[heap]") == 0) {
    //   GDB_PRINTF("[heap] %s %lx-%lx\n", flags, from, to);
    //   pbvt_track_range((void *)from, to - from, prot);
    //   continue;
    // }

    if (strcmp(name, "[stack]") == 0) {
      GDB_PRINTF("[stack] %s %lx-%lx\n", flags, from, to);
      pbvt_track_range((void *)from, to - from, prot);
      continue;
    }

    // TODO: This is broken currently. pbvt supports it but we do not, we need a
    // way to check whether our target is segfaulting because we are controlling
    // a region, or if it is a legitimate crash.
    //  if (strstr(name, APP_NAME) != NULL) {
    //    GDB_PRINTF("[%s] %s %lx-%lx %s\n", APP_NAME, flags, from, to, name);
    //    pbvt_track_range((void *)from, to - from, prot);
    //    continue;
    //  }

    GDB_PRINTF("[ignore] %s %lx-%lx %s\n", flags, from, to, name);
  }
  close(maps);

  GDB_PRINTF("Done tracking memory...\n", 0);

  pbvt_commit();
  pbvt_branch_commit("main");

  // Initialize gdbctx
  gdbctx gctx = {0};
  gdbctx *ctx = &gctx;

  ctx->ppid = ppid;
  ctx->stopped = 1;
  ctx->regs = pbvt_calloc(1, sizeof(struct user_regs_struct));
  ctx->fpregs = pbvt_calloc(1, sizeof(struct user_fpregs_struct));

  // TODO: Calculate this based on size of executable memory
  ctx->sketch_sz = 0x4000;
  uint64_t *alloc = pbvt_calloc(ctx->sketch_sz * SKETCH_COL, sizeof(uint64_t));
  for (int i = 0; i < SKETCH_COL; ++i)
    ctx->sketch[i] = &alloc[i * ctx->sketch_sz];

  gdb_save_state(ctx);

  xptrace(PTRACE_CONT, ctx->ppid, NULL, NULL);
  waitpid(ctx->ppid, &status, 0);
  GDB_PRINTF("status: %d\n", status);
  ctx->regs->rax = 0;
  xptrace(PTRACE_GETREGS, ctx->ppid, NULL, ctx->regs);
  GDB_PRINTF("rip: %p\n", ctx->regs->rip);

  pt_init(ctx);
  ctx->pim = pim;
  ctx->asid = asid;

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
  ctx->fd = cfd;

  GDB_PRINTF("done.\n", 0);

  ctx->timerfd = timerfd_create(CLOCK_REALTIME, 0);
  gdb_arm_timer(ctx);

  struct pollfd pollfds[3] = {0};
  pollfds[0].fd = cfd;
  pollfds[0].events = POLLIN | POLLERR;
  pollfds[1].fd = ctx->timerfd;
  pollfds[1].events = POLLIN | POLLERR;

  char gdb_buf[0x100];

  // Main event loop
  for (;;) {
    if (poll(pollfds, 2, -1) < 0)
      xperror("poll(wrapper)");

    // Socket
    if (pollfds[0].revents & POLLERR)
      xperror("POLLERR in socket");
    if (pollfds[0].revents & POLLIN) {
      int nbytes = read(pollfds[0].fd, gdb_buf, sizeof(gdb_buf) - 1);
      if (nbytes < 0)
        xperror("read");
      if (nbytes == 0)
        break;
      gdb_buf[nbytes] = '\0';
      GDB_PRINTF("Remote: \"%s\", n: %d\n", gdb_buf, nbytes);
      gdb_handle_packet(ctx, gdb_buf, nbytes);
      continue;
    }

    // Process hit syscall, handle this before our timer in case the process
    // is already stopped on a syscall.
    if (waitpid(ctx->ppid, &status, WNOHANG) > 0) {
      GDB_PRINTF("Handle signal\n", 0);

      // Stopped by GDB
      // if (ctx->stopped)
      //   continue;
      gdb_save_state(ctx);

      GDB_PRINTF("Status: %d, sig: %d\n", status, WSTOPSIG(status),
                 WIFSTOPPED(status));

      if (WSTOPSIG(status) == SIGTRAP) {
        Breakpoint *bp = NULL;
        for (size_t i = 0; i < ctx->bps_sz; ++i) {
          if (ctx->regs->rip - 1 == ctx->bps[i].ip) {
            bp = &ctx->bps[i];
            break;
          }
        }

        if (bp) {
          GDB_PRINTF("Hit breakpoint! RIP: %.16lx BP: %.16lx\n",
                     ctx->regs->rip - 1, bp->ip);
          ctx->regs->rip -= 1;
          xptrace(PTRACE_SETREGS, ctx->ppid, NULL, ctx->regs);
          breakpoint_del(ctx,bp);
          gdb_send_packet(ctx, "S05");
          ctx->stopped = 1;
          continue;
        }
      } else if (WSTOPSIG(status) == SIGSEGV) {
        abort();
      }

      GDB_PRINTF("Entering syscall:\trax: %.16lx rdi: %.16lx rsi: "
                 "%.16lx ...\n",
                 ctx->regs->orig_rax, ctx->regs->rdi, ctx->regs->rsi);

      xptrace(PTRACE_SYSCALL, ctx->ppid, NULL, NULL);
      waitpid(ctx->ppid, &status, 0);
      gdb_save_state(ctx);

      GDB_PRINTF("Exiting syscall:\trax: %.16lx\n", ctx->regs->rax);

      gdb_continue(ctx);

      continue;
    }

    // Timer
    if (pollfds[1].revents & POLLERR)
      xperror("POLLERR in timer");
    if (pollfds[1].revents & POLLIN) {
      uint64_t expiry;
      read(pollfds[1].fd, &expiry, sizeof(expiry));

      if (ctx->stopped)
        continue;

      GDB_PRINTF("Snapshot because of timeout\n", 0);

      gdb_pause(ctx);
      gdb_save_state(ctx);
      gdb_continue(ctx);

      continue;
    }

    GDB_PRINTF("Got poll but not handled!", 0);
  }

  return 0;
}

__attribute__((constructor)) static void wrapper_init(void) {
  char c;
  gdbstub_stk = mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE,
                     MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  ppid = getpid();
  if (pipe(fildes) < 0)
    xperror("pipe");
  clone(gdbstub, gdbstub_stk + STACK_SIZE, CLONE_VM, NULL);
  read(fildes[0], &c, 1);
}

__attribute__((destructor)) static void wrapper_fini(void) {
  if (munmap(gdbstub_stk, STACK_SIZE) == -1)
    xperror("munmap");
}
