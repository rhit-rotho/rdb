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

#define xperror(en, msg)                                                       \
  do {                                                                         \
    errno = en;                                                                \
    perror(msg);                                                               \
    exit(EXIT_FAILURE);                                                        \
  } while (0)

static void start_trace(void);

int uffd;

// mprotect((uintptr_t)entry & ~(sysconf(_SC_PAGE_SIZE) - 1),
// sysconf(_SC_PAGE_SIZE), PROT_READ | PROT_WRITE); uint8_t patch[] =
// {0xc2}; memcpy(entry, patch, sizeof(patch) / sizeof(uint8_t));
// mprotect((uintptr_t)entry & ~(sysconf(_SC_PAGE_SIZE) - 1),
// sysconf(_SC_PAGE_SIZE), PROT_READ | PROT_EXEC);
//   void *entry = (void *)getauxval(AT_ENTRY);

__attribute__((constructor)) static void wrapper_init(void) {
  uffd = syscall(SYS_userfaultfd, 0);
  if (uffd < 0)
    perror("userfaultfd");

  struct uffdio_api api = {.api = UFFD_API, .features = 0, .ioctls = 0};
  if (ioctl(uffd, UFFDIO_API, &api) < 0)
    perror("ioctl");

  void *test = mmap(NULL, sysconf(_SC_PAGE_SIZE), PROT_READ,
                    MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  if (test == MAP_FAILED)
    xperror(test, "mmap");

  struct uffdio_register reg = {.range.start = test,
                                .range.len = sysconf(_SC_PAGE_SIZE),
                                .mode = UFFDIO_REGISTER_MODE_WP};

  if (ioctl(uffd, UFFDIO_REGISTER, &reg) == -1)
    xperror(-1, "ioctl");
  int pid = vfork();
  if (pid) {
    sleep(1);
    ((uint32_t *)test)[0] = 0x10;
  } else {
    for (;;) {
      struct pollfd pollfd = {.fd = uffd, .events = POLLIN};
      struct uffd_msg msg;
      int nready = poll(&pollfd, 1, -1);
      if (nready == -1)
        xperror(nready, "poll");
      printf("nready: %d", nready);
      int nread = read(uffd, &msg, sizeof(msg));

      if (msg.event != UFFD_EVENT_PAGEFAULT)
        printf("Unexpected event\n");

      struct uffdio_copy uffdio_copy = {};
      ioctl(uffd, UFFDIO_COPY_MODE_WP, &uffdio_copy);
    }
  }

  FILE *maps = fopen("/proc/self/maps", "r");
  if (maps == NULL)
    xperror(maps, "open");
  char buf[PROCMAPS_LINE_MAX_LENGTH];
  while (fgets(buf, PROCMAPS_LINE_MAX_LENGTH, maps)) {
    char flags[5] = {0};
    char name[PATH_MAX] = {0};
    uint64_t from, to;
    uint32_t major, minor, offset, inode;
    sscanf(buf, "%llx-%llx %4c %x %x:%x %d %[^\n]", &from, &to, &flags, &offset,
           &major, &minor, &inode, name);

    bool is_r = flags[0] == 'r';
    bool is_w = flags[1] == 'w';
    bool is_x = flags[2] == 'x';

    if (!strcmp(name, ""))
      continue;
    if (!strcmp(name, "[heap]"))
      continue;
    if (!strcmp(name, "/usr/lib/libc.so.6"))
      continue;
    if (!strcmp(name, "[stack]"))
      continue;
    if (!strcmp(name, "/home/omar/projects/rdb/libwrapper.so"))
      continue;
    if (!strcmp(name, "/usr/lib/ld-linux-x86-64.so.2"))
      continue;
    if (is_w) {
      printf("%s %llx-%llx %s\n", flags, from, to, name);
      mprotect(from, to - from,
               (is_r ? PROT_READ : 0) | (is_x ? PROT_EXEC : 0));
    }
  }
  fclose(maps);

  // spawn debugging thread
  // https://yarchive.net/comp/linux/ptrace_self_attach.html
  //   int pid = vfork();
  //   if (pid == -1)
  //     perror("vfork");

  //   if (pid == 0) { // we're the child
  //                   // printf("sending signal, sleeping\n");
  //     // return;
  //     // sleep(1);
  //     pause();
  //     // kill(getpid(), SIGUSR1);
  //     // kill(pid, SIGUSR1);
  //     // procmaps_iterator *iter = pmparser_parse(pid);
  //     // start_trace();
  //     exit(-1);
  //   } else {
  //     printf("hello!\n");
  //     // signal(SIGUSR1, empty);
  //     // pause();
  //     // perror("signal");
  //     // printf("let's go!\n");
  //     return; // continue executing main
  //   }
}

__attribute__((destructor)) static void wrapper_fini(void) {}

static void start_trace(void) {
  time_t t;
  if (prctl(PR_SET_NAME, "tracer"))
    perror("prctl");

  //   if (ptrace(getppid(), PTRACE_ATTACH))
  //     perror("ptrace");
  //   if (ptrace(getppid(), PTRACE_DETACH))
  //     perror("ptrace");
  exit(-1);

  int threads = open("/proc/self/maps", O_RDONLY);
  if (threads < 0)
    perror("open");

  FILE *cstdout = fopen("stdout.txt", "w");
  FILE *cstderr = fopen("stderr.txt", "w");
  setbuf(cstdout, NULL);
  setbuf(cstderr, NULL);

  // let's have some fun
  //   void *entry = (void *)getauxval(AT_ENTRY);
  //   csh handle;
  //   cs_insn *insn;
  //   size_t count;
  //   if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
  //     return -1;
  //   count = cs_disasm(handle, entry, 0x80, entry, 0, &insn);
  //   if (count > 0) {
  //     size_t j;
  //     for (j = 0; j < count; j++) {
  //       fprintf(cstdout, "0x%" PRIx64 ":\t%s\t\t%s\n", insn[j].address,
  //               insn[j].mnemonic, insn[j].op_str);
  //     }
  //     cs_free(insn, count);
  //   } else
  //     fprintf(cstderr, "ERROR: Failed to disassemble given code!\n");
  //   cs_close(&handle);

  for (;;) {
    sleep(1);
    time(&t);
    fprintf(cstdout, "%ld\n", t);
  }
}
