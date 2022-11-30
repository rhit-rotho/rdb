#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define xperror(msg)                                                           \
  do {                                                                         \
    perror(msg);                                                               \
    exit(EXIT_FAILURE);                                                        \
  } while (0)

#define xptrace(req, pid, addr, data)                                          \
  do {                                                                         \
    if (ptrace(req, pid, addr, data) == -1) {                                  \
      xperror(#req);                                                           \
    }                                                                          \
  } while (0)

int main(int argc, char **argv) {
  if (argc < 2) {
    printf("./rdb [pid]\n");
    return EXIT_FAILURE;
  }

  setbuf(stdout, NULL);
  setbuf(stderr, NULL);

  int pid = atoll(argv[1]);
  printf("Attaching to %d...", pid);
  xptrace(PTRACE_ATTACH, pid, NULL, NULL);

  int status;
  waitpid(pid, &status, 0);

  printf("Status: %d\n", status);

  struct user_regs_struct regs;

  time_t t;
  for (int i = 0; i < 1; ++i) {
    xptrace(PTRACE_INTERRUPT, pid, NULL, NULL);
    waitpid(pid, &status, 0);
    xptrace(PTRACE_GETREGS, pid, &regs, NULL);
    printf("%llx\n", regs.rax);
    sleep(1);
    time(&t);
    xptrace(PTRACE_CONT, pid, NULL, NULL);
  }

  xptrace(PTRACE_DETACH, pid, NULL, NULL);
  waitpid(pid, &status, 0);

  printf("Detached!");
  return 0;
}
