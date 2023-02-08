#define _GNU_SOURCE
#include <arpa/inet.h>
#include <assert.h>
#include <capstone/capstone.h>
#include <fcntl.h>
#include <intel-pt.h>
#include <limits.h>
#include <linux/perf_event.h>
#include <linux/sched.h>
#include <netinet/in.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include "gdbstub.h"
#include "pbvt.h"

#define STACK_SIZE (8 * 1024 * 1024)
#define PROCMAPS_LINE_MAX_LENGTH (PATH_MAX + 100)

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

int handle_events(struct pt_insn_decoder *decoder, int status) {
  while (status & pts_event_pending) {
    struct pt_event event;

    status = pt_insn_event(decoder, &event, sizeof(event));
    if (status < 0)
      break;

    GDB_PRINTF("event: %d\n", event.type);
  }

  return status;
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

  struct pt_image *pim = pt_image_alloc("test-app");

  char buf[PROCMAPS_LINE_MAX_LENGTH];
  uint64_t image_start;
  while (read_line(maps, buf, PROCMAPS_LINE_MAX_LENGTH)) {
    char flags[5] = {0};
    char name[PATH_MAX] = {0};
    uint64_t from, to, inode;
    uint32_t major, minor, offset;
    sscanf(buf, "%lx-%lx %4c %x %x:%x %ld %[^\n]", &from, &to, flags, &offset,
           &major, &minor, &inode, name);

    // bool is_r = flags[0] == 'r';
    bool is_w = flags[1] == 'w';
    bool is_x = flags[2] == 'x';

    if (strstr(name, "test-app") && image_start == 0) {
      image_start = from;
      GDB_PRINTF("Image base: %.16lx\n", image_start);
    }

    // PT decoder add range
    if (is_x && strstr(name, "test-app")) {
      GDB_PRINTF("[test-app] (offset: %.6lx) %s %lx-%lx '%s'\n",
                 from - image_start, flags, from, to, name);
      if (pt_image_add_file(pim, name, from - image_start, to - from, NULL,
                            from) < 0)
        GDB_PRINTF("pt_image_add_file failed!\n", 0);
    }

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
  gdbctx *ctx = &gctx;

  ctx->ppid = ppid;
  ctx->stopped = 1;
  ctx->regs = pbvt_calloc(1, sizeof(struct user_regs_struct));
  ctx->fpregs = pbvt_calloc(1, sizeof(struct user_fpregs_struct));
  gdb_save_state(ctx);

  xptrace(PTRACE_CONT, ctx->ppid, NULL, NULL);
  waitpid(ctx->ppid, &status, 0);
  GDB_PRINTF("status: %d\n", status);
  ctx->regs->rax = 0;
  xptrace(PTRACE_GETREGS, ctx->ppid, NULL, ctx->regs);
  GDB_PRINTF("rip: %p\n", ctx->regs->rip);

  struct perf_event_attr attr = {0};
  attr.size = sizeof(attr);

  attr.exclude_kernel = 1;
  attr.exclude_hv = 1;
  attr.exclude_idle = 1;

  // TODO: Replace with read to /sys/bus/event_source/devices/intel_pt/type
  attr.type = 8;

  attr.config = 0;
  // /sys/bus/event_source/devices/intel_pt/format/pt
  attr.config |= 1 << 0;
  // /sys/bus/event_source/devices/intel_pt/format/tsc
  attr.config |= 1 << 10;
  // /sys/bus/event_source/devices/intel_pt/format/branch
  attr.config |= 1 << 13;
  // /sys/bus/event_source/devices/intel_pt/format/psb_period
  attr.config |= 0 << 24;

  // PSB period: expect every 2**(value+11) bytes

  attr.disabled = 0;

  int pfd = syscall(SYS_perf_event_open, &attr, ctx->ppid, -1, -1, 0);
  if (pfd < 0)
    xperror("SYS_perf_event_open");

  struct perf_event_mmap_page *header;
  void *base, *data, *aux;
  int n = 0, m = 16; // data size, aux size

  base = mmap(NULL, (1 + 2 * n) * PAGE_SIZE, PROT_WRITE, MAP_SHARED, pfd, 0);
  if (base == MAP_FAILED)
    xperror("mmap");

  header = base;
  data = base + header->data_offset;

  header->aux_offset = header->data_offset + header->data_size;
  header->aux_size = (2 * m) * PAGE_SIZE;

  // PROT_READ - circular buffer
  // PROT_READ|PROT_WRITE - linear buffer
  aux = mmap(NULL, header->aux_size, PROT_READ | PROT_WRITE, MAP_SHARED, pfd,
             header->aux_offset);
  if (aux == MAP_FAILED)
    xperror("mmap");

  GDB_PRINTF("aux_size:%lx\n", header->aux_size);
  GDB_PRINTF("aux_head:%lx\n", header->aux_head);

  // xptrace(PTRACE_SYSCALL, ctx->ppid, NULL, NULL);
  xptrace(PTRACE_CONT, ctx->ppid, NULL, NULL);
  // xptrace(PTRACE_SINGLESTEP, ctx->ppid, NULL, NULL);
  usleep(100);
  xptrace(PTRACE_INTERRUPT, ctx->ppid, NULL, NULL);
  waitpid(ctx->ppid, &status, 0);

  struct pt_insn_decoder *decoder;
  struct pt_config config;
  int errcode;

  memset(&config, 0, sizeof(config));
  config.size = sizeof(config);
  config.begin = aux;
  config.end = aux + header->aux_size;
  config.decode.callback = NULL;
  config.decode.context = NULL;

  decoder = pt_insn_alloc_decoder(&config);
  GDB_PRINTF("decoder: %p\n", decoder);
  GDB_PRINTF("pt_insn_set_image(decoder, pim) => %d\n",
             pt_insn_set_image(decoder, pim));

  csh handle;
  if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
    xperror("cs_open");
  cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
  cs_insn *tinsn = cs_malloc(handle);

  for (;;) {
    // printf("%.16lx\n", header->aux_head);
    if (header->aux_head != header->aux_tail) {
      GDB_PRINTF("head: %p\n", header->aux_head);
      GDB_PRINTF("tail: %p\n", header->aux_tail);
      for (int j = 0; j < 5; ++j) {
        GDB_PRINTF("", 0);
        for (int i = 0; i < 0x20; ++i)
          printf("%.2x ", ((uint8_t *)aux)[j * 0x20 + i]);
        printf("\n");
      }
      int insn_status = pt_insn_sync_forward(decoder);

      for (;;) {
        struct pt_insn insn;

        insn_status = handle_events(decoder, insn_status);
        if (insn_status < 0) {
          GDB_PRINTF("%d %s\n", insn_status, pt_errstr(-insn_status));
          break;
        }

        errcode = pt_insn_next(decoder, &insn, sizeof(insn));
        if (errcode < 0) {
          GDB_PRINTF("%d %s\n", errcode, pt_errstr(-errcode));
          if (-errcode == pte_eos)
            goto pt_end;

          break;
        }

        uint64_t *code = insn.ip;
        uint64_t address = insn.ip;
        size_t sz = 0x10; // max size of x86 insn is 15 bytes
        if (!cs_disasm_iter(handle, &code, &sz, &address, tinsn)) {
          GDB_PRINTF("fail: %s\n", cs_strerror(cs_errno(handle)));
          break;
        }
        // GDB_PRINTF("0x%.16lx:\t%s\t%s\n", insn.ip, tinsn->mnemonic,
        // tinsn->op_str);
      }
      uint64_t insn_offset;
      pt_insn_get_offset(decoder, &insn_offset);
      GDB_PRINTF("insn_offset: %p, aux_size: %p\n", insn_offset,
                 header->aux_size);
      // memmove(aux, aux+insn_offset, header->aux_size - insn_offset);
      header->aux_tail = insn_offset;
      // header->aux_head = header->aux_size - insn_offset;
      // pt_insn_sync_set(decoder, 0);
      // break;
    }
  }

pt_end:
  GDB_PRINTF("Done.\n", 0);
  return 0;

  // ioctl(pfd, PERF_EVENT_IOC_DISABLE, 0);

  uint64_t rd_val;
  int nbytes = read(pfd, &rd_val, sizeof(rd_val));
  printf("read: %d %d\n", nbytes, rd_val);

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

  int timerfd = timerfd_create(CLOCK_REALTIME, 0);
  struct itimerspec arm = {0};
  arm.it_interval.tv_sec = 10;
  arm.it_interval.tv_nsec = 0;
  // arm.it_interval.tv_nsec = 1000 * 1000 * 10;
  arm.it_value.tv_sec = 10;
  arm.it_value.tv_nsec = 0;
  // arm.it_value.tv_nsec = 1000 * 1000 * 10;
  if (timerfd_settime(timerfd, 0, &arm, NULL) < 0)
    xperror("timerfd_settime");

  sigset_t mask = {0};
  sigemptyset(&mask);
  sigaddset(&mask, SIGCHLD);
  sigprocmask(SIG_BLOCK, &mask, NULL);
  int sfd = signalfd(-1, &mask, 0);
  if (sfd < 0)
    xperror("signalfd");

  // TODO: Add signalfd for handling segfaults, syscalls, and signals
  struct pollfd pollfds[3] = {0};
  pollfds[0].fd = cfd;
  pollfds[0].events = POLLIN | POLLERR;
  pollfds[1].fd = sfd;
  pollfds[1].events = POLLIN | POLLERR;
  pollfds[2].fd = timerfd;
  pollfds[2].events = POLLIN | POLLERR;

  char gdb_buf[0x100];

  size_t snap_counter = 0;

  // Main event loop
  for (;;) {
    if (poll(pollfds, 3, -1) < 0)
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

    // Process hit syscall, handle this before our timer in case the process is
    // already stopped on a syscall.
    if (pollfds[1].revents & POLLERR)
      xperror("POLLERR in signalfd");
    if (pollfds[1].revents & POLLIN) {
      GDB_PRINTF("Handle signal\n", 0);
      struct signalfd_siginfo ssi;
      read(pollfds[1].fd, &ssi, sizeof(ssi));

      // Stopped by GDB
      if (ctx->stopped)
        continue;

      GDB_PRINTF("ssi.ssi_signo: %d ssi.ssi_code: %d\n", ssi.ssi_signo,
                 ssi.ssi_code);

      waitpid(ctx->ppid, &status, 0);
      ctx->stopped = 1;
      gdb_save_state(ctx);

      GDB_PRINTF("Entering syscall:\trax: %.16lx rdi: %.16lx rsi: "
                 "%.16lx ...\n",
                 ctx->regs->orig_rax, ctx->regs->rdi, ctx->regs->rsi);

      xptrace(PTRACE_SYSCALL, ctx->ppid, NULL, NULL);
      waitpid(ctx->ppid, &status, 0);
      gdb_save_state(ctx);

      GDB_PRINTF("Exiting syscall:\trax: %.16lx\n", ctx->regs->rax);

      gdb_continue(ctx);

      snap_counter += 1;
      if (snap_counter % 100 == 0)
        pbvt_stats();
      continue;
    }

    // Timer
    if (pollfds[2].revents & POLLERR)
      xperror("POLLERR in timer");
    if (pollfds[2].revents & POLLIN) {
      uint64_t expiry;
      read(pollfds[2].fd, &expiry, sizeof(expiry));

      if (ctx->stopped)
        continue;

      gdb_pause(ctx);
      gdb_save_state(ctx);
      gdb_continue(ctx);

      snap_counter += 1;
      if (snap_counter % 100 == 0)
        pbvt_stats();
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
