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

#include "gdbstub.h"
#include "pbvt.h"

#define STACK_SIZE (8 * 1024 * 1024)
#define PROCMAPS_LINE_MAX_LENGTH (PATH_MAX + 100)
#define UNUSED(x) (void)(x)

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
