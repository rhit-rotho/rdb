#define _GNU_SOURCE
#include <linux/sched.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <unistd.h>

#include <strings.h>

#include "pbvt.h"

#define STACK_SIZE (8 * 1024 * 1024)
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

typedef struct gdbstub_args {
  ucontext_t *ucp;
} gdbstub_args;

void sighandler(int signo) {
  UNUSED(signo);
  printf("[%d] I got the signal!\n", gettid());
  exit(-1);
}

void gdbstub(void) {
  // UNUSED(args);

  signal(SIGINT, sighandler);

  // printf("Inside the binary!\n");

  for (;;) {
    printf("[gdbstub %d (ppid:%d)]\n", gettid(), getppid());
    sleep(1);
  }

  return;
}

stack_t gdbstub_stk;
ucontext_t uctx_main, uctx_gdbstub;

int tmpfunc(void *args) {
  UNUSED(args);
  // FIXME: Race, should just wait for parent to signal that uctx_main is
  // initialized correctly.
  sleep(1);
  setcontext(&uctx_main);
  return 0;
}

__attribute__((constructor)) static void wrapper_init(void) {
  // pbvt_init();
  // pbvt_branch_commit("main");

  setbuf(stdout, NULL);
  setbuf(stderr, NULL);

  gdbstub_stk.ss_sp = mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE,
                           MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  gdbstub_stk.ss_size = STACK_SIZE;

  if (gdbstub_stk.ss_sp == MAP_FAILED)
    xperror("mmap");

  getcontext(&uctx_gdbstub);
  getcontext(&uctx_main);
  uctx_gdbstub.uc_stack = gdbstub_stk;
  uctx_gdbstub.uc_link = NULL;
  makecontext(&uctx_gdbstub, gdbstub, 0);

  void *tmp_stk = mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE,
                       MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  clone(tmpfunc, tmp_stk + STACK_SIZE, CLONE_THREAD | CLONE_SIGHAND | CLONE_VM,
        NULL);
  swapcontext(&uctx_main, &uctx_gdbstub);

  if (munmap(tmp_stk, STACK_SIZE) == -1)
    xperror("munmap");

  printf("[%d] %d\n", gettid(), __LINE__);

  sigset_t mask;
  sigprocmask(SIG_BLOCK, &mask, NULL);
  printf("Blocking all signals\n");
  sigfillset(&mask);
  sigprocmask(SIG_BLOCK, NULL, &mask);
}

__attribute__((destructor)) static void wrapper_fini(void) {
  // if (munmap(gdbstub_stk.ss_sp, STACK_SIZE) == -1)
  //   xperror("munmap");
}
