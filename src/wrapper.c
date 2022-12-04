#define _GNU_SOURCE
#include <fcntl.h>
#include <limits.h>
#include <linux/sched.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/wait.h>
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
    // printf("%s\n", buf);
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
      printf("[stack] %s %lx-%lx %s\n", flags, from, to, name);
      pbvt_track_range((void *)from, to - from);
      continue;
    }

    if (strcmp(name, "[stack]") == 0) {
      printf("[stack] %s %lx-%lx %s\n", flags, from, to, name);
      pbvt_track_range((void *)from, to - from);
      continue;
    }

    // if (strstr(name, "test-app") != NULL) {
    //   printf("[test-app] %s %lx-%lx %s\n", flags, from, to, name);
    //   pbvt_track_range((void *)from, to - from);
    //   continue;
    // }

    printf("[ignore] %s %lx-%lx %s\n", flags, from, to, name);
  }
  close(maps);

  pbvt_commit();
  pbvt_branch_commit("main");
  sleep(1);
  xptrace(PTRACE_CONT, ppid, NULL, NULL);

  struct user_regs_struct *regs =
      pbvt_calloc(1, sizeof(struct user_regs_struct));
  struct user_fpregs_struct *fpregs =
      pbvt_calloc(1, sizeof(struct user_fpregs_struct));

  for (int i = 0;; ++i) {
    usleep(1000);
    xptrace(PTRACE_INTERRUPT, ppid, NULL, NULL);
    waitpid(ppid, &status, 0);

    // Cause page fault on our regs, since ptrace will not correctly trigger our
    // uffd_monitor.
    regs->rax = 0;
    fpregs->cwd = 0;
    xptrace(PTRACE_GETREGS, ppid, NULL, regs);
    xptrace(PTRACE_GETFPREGS, ppid, NULL, fpregs);

    Commit *c = pbvt_commit();
    if (i % 40 == 0) {
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
  // clone(gdbstub, gdbstub_stk + STACK_SIZE,
  //       CLONE_VM | CLONE_FILES | CLONE_FS | CLONE_PARENT | CLONE_SIGHAND,
  //       NULL);
}

__attribute__((destructor)) static void wrapper_fini(void) {
  // if (munmap(gdbstub_stk.ss_sp, STACK_SIZE) == -1)
  //   xperror("munmap");
}
