#define _GNU_SOURCE
#include <capstone/capstone.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/limits.h>
#include <linux/userfaultfd.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define PROCMAPS_LINE_MAX_LENGTH (PATH_MAX + 100)

#define xperror(msg)                                                           \
  do {                                                                         \
    perror(msg);                                                               \
    exit(EXIT_FAILURE);                                                        \
  } while (0)

int main(int argc, char **argv) {
  if (argc < 2)
    printf("./rdb [pid]");

  int pid = atoll(argv[1]);
  printf("Attaching to %d...", pid);
  if (ptrace(PTRACE_ATTACH, pid) == -1)
    xperror("ptrace");

  //   if (ptrace(getppid(), PTRACE_ATTACH))
  //     perror("ptrace");
  //   if (ptrace(getppid(), PTRACE_DETACH))
  //     perror("ptrace");

  time_t t;
  for (int i = 0; i < 10; ++i) {
    sleep(1);
    time(&t);
  }

  if (ptrace(PTRACE_DETACH, pid) == -1)
    xperror("ptrace");
}
