#define _GNU_SOURCE
#include <arpa/inet.h>
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
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <time.h>
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

void *gdbstub_stk;
pid_t ppid;

int gdbstub(void *args) {
  UNUSED(args);

  int status;

  // Immediately sezie and interrupt process, this is so we can easily interrupt
  // the process later.
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
  sleep(1);
  xptrace(PTRACE_CONT, ppid, NULL, NULL);

  struct user_regs_struct *regs =
      pbvt_calloc(1, sizeof(struct user_regs_struct));
  struct user_fpregs_struct *fpregs =
      pbvt_calloc(1, sizeof(struct user_fpregs_struct));

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
  // struct sockaddr_in caddr;
  // socklen_t clen = sizeof(caddr);
  int cfd = accept(gdb_socket, NULL, NULL);
  if (cfd < 0)
    xperror("accept");

  printf("done.\n");

  int timer = timerfd_create(CLOCK_MONOTONIC, 0);
  struct itimerspec arm = {0};
  arm.it_interval.tv_nsec = 10000 * 1000;
  timerfd_settime(timer, 0, &arm, NULL);

  // TODO: Add signalfd for handling segfaults, syscalls, and signals
  struct pollfd pollfds[2] = {0};
  pollfds[0].fd = timer;
  pollfds[1].events = POLLIN | POLLERR;
  pollfds[1].fd = cfd;
  pollfds[1].events = POLLIN | POLLERR;

  char gdb_buf[0x100];

  for (;;) {
    if (poll(pollfds, 2, -1) < 0)
      xperror("poll(wrapper)");

    // Timer
    if (pollfds[0].revents & POLLERR)
      xperror("POLLERR in timer");
    if (pollfds[0].revents & POLLIN) {
    }

    // socket
    if (pollfds[1].revents & POLLERR)
      xperror("POLLERR in socket");
    if (pollfds[1].revents & POLLIN) {
      // TODO: Implement the rest of gdb's wire protocol
      int nbytes = read(pollfds[1].fd, gdb_buf, sizeof(gdb_buf) - 1);
      if (nbytes < 0)
        xperror("read");
      gdb_buf[nbytes] = '\0';
      printf("gdb: \"%s\"\n", gdb_buf);
      if (strncmp(gdb_buf, "$qSupported:", 12) == 0) {
        write(pollfds[1].fd, "+$#00", 5);
        printf("wrote out\n");
        continue;
      }
      if (strncmp(gdb_buf, "+", 1) == 0) {
        write(pollfds[1].fd, "+$#00", 5);
        continue;
      }

      continue;
    }

    printf("Got poll but not handled!");
  }

  for (int i = 0;; ++i) {
    xptrace(PTRACE_INTERRUPT, ppid, NULL, NULL);
    waitpid(ppid, &status, 0);

    // Cause page fault on our regs, since ptrace will not correctly trigger our
    // uffd_monitor.
    regs->rax = 0;
    fpregs->cwd = 0;
    xptrace(PTRACE_GETREGS, ppid, NULL, regs);
    xptrace(PTRACE_GETFPREGS, ppid, NULL, fpregs);

    Commit *c = pbvt_commit();
    if (i % 10 == 0) {
      printf("[gdb: pid:%d tid:%d ppid:%d] Alive!\n", getpid(), gettid(),
             getppid());
      printf("[gdb] State: %.16lx\n", c->hash);
      pbvt_stats();
    }
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
  // if (munmap(gdbstub_stk.ss_sp, STACK_SIZE) == -1)
  //   xperror("munmap");
}
