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

#include "fasthash.h"
#include "gdbstub.h"
#include "pbvt.h"

// #define CAPSTONE_DEBUG

#define APP_NAME "ptc"

#define STACK_SIZE (8 * 1024 * 1024)
#define PROCMAPS_LINE_MAX_LENGTH (PATH_MAX + 100)

#define HCOUNTER_ROWS (0x4)
#define HCOUNTER_COLS (0x1000)
#define COUNTER_SIZE (0x1000)

#define MIN(a, b) ((a) < (b) ? (a) : (b))

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

csh handle;
cs_insn tinsn;
size_t insn_counter;
int process_block(struct pt_block *block,
                  struct pt_image_section_cache *iscache, uint64_t *fip) {
  uint16_t ninsn;
  uint64_t ip;

  ip = block->ip;
  for (ninsn = 0; ninsn < block->ninsn; ++ninsn) {
    struct pt_insn insn;

    memset(&insn, 0, sizeof(insn));
    insn.speculative = block->speculative;
    insn.isid = block->isid;
    insn.mode = block->mode;
    insn.ip = ip;

    if (block->truncated && ((ninsn + 1) == block->ninsn)) {
      insn.truncated = 1;
      insn.size = block->size;

      memcpy(insn.raw, block->raw, insn.size);
    } else {
      int size;
      size = pt_iscache_read(iscache, insn.raw, sizeof(insn.raw), insn.isid,
                             insn.ip);
      if (size < 0)
        return size;

      insn.size = (uint8_t)size;
    }

#ifdef CAPSTONE_DEBUG
    const uint8_t *code = (uint8_t *)ip;
    uint64_t address = ip;
    size_t sz = 0x10; // max size of x86 insn is 15 bytes
    if (!cs_disasm_iter(handle, &code, &sz, &address, tinsn)) {
      GDB_PRINTF("cs_disasm_iter: %s\n", cs_strerror(cs_errno(handle)));
      break;
    }
    GDB_PRINTF("0x%.16lx:\t%s\t%s\n", insn.ip, tinsn->mnemonic, tinsn->op_str);
    ip += tinsn->size;
#else
    ip += insn.size;
#endif
    insn_counter++;
  }

  *fip = ip;

  return 0;
}

int process_full_trace(uint8_t *buf, size_t n,
                       struct pt_image_section_cache *pim, int asid) {
  // UNUSED(bitmap);

  struct pt_block_decoder *decoder;
  struct pt_config config;

  memset(&config, 0, sizeof(config));
  config.size = sizeof(config);
  config.begin = buf;
  config.end = buf + n;
  config.decode.callback = NULL;
  config.decode.context = NULL;

  decoder = pt_blk_alloc_decoder(&config);
  int pim_status =
      pt_image_add_cached(pt_blk_get_image(decoder), pim, asid, NULL);
  if (pim_status < 0) {
    GDB_PRINTF("pt_image_add_cached(%d): %s\n", asid, pt_errstr(pim_status));
    exit(-1);
  }

  uint64_t fip = 0xbad0bad0bad0bad0;
  int wstatus = pt_blk_sync_forward(decoder);
  if (wstatus < 0) {
    GDB_PRINTF("%s\n", pt_errstr(-wstatus));
    return -1;
  }

  for (;;) {
    for (;;) {
      struct pt_block block;
      int errcode;

      wstatus = handle_events(decoder, wstatus);
      if (wstatus < 0) {
        // fip = __LINE__;
        break;
      }

      wstatus = pt_blk_next(decoder, &block, sizeof(block));
      errcode = process_block(&block, pim, &fip);
      if (wstatus == -pte_eos) {
        // fip = __LINE__;
        break;
      }
      if (errcode < 0)
        wstatus = errcode;
      if (wstatus < 0)
        break;
    }
    if (wstatus == -pte_eos)
      break;
    if (wstatus < 0) {
      GDB_PRINTF("%s\n", wstatus, pt_errstr(wstatus));
      break;
    }

    wstatus = pt_blk_sync_forward(decoder);
    if (wstatus < 0) {
      GDB_PRINTF("%s\n", pt_errstr(-wstatus));
      break;
    }
  }

  GDB_PRINTF("Final ip from decode: 0x%.16lx\n", fip);
  GDB_PRINTF("Finished processing %d instructions.\n", insn_counter);

  pt_blk_free_decoder(decoder);

  return 0;
}

int handle_events(struct pt_block_decoder *decoder, int status) {
  while (status & pts_event_pending) {
    struct pt_event event;

    status = pt_blk_event(decoder, &event, sizeof(event));
    if (status < 0)
      break;
    // GDB_PRINTF("event: %d\n", event.type);
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

    if (strcmp(name, "[heap]") == 0) {
      GDB_PRINTF("[heap] %s %lx-%lx\n", flags, from, to);
      pbvt_track_range((void *)from, to - from, prot);
      continue;
    }

    if (strcmp(name, "[stack]") == 0) {
      GDB_PRINTF("[stack] %s %lx-%lx\n", flags, from, to);
      pbvt_track_range((void *)from, to - from, prot);
      continue;
    }

    if (strstr(name, APP_NAME) != NULL) {
      GDB_PRINTF("[%s] %s %lx-%lx %s\n", APP_NAME, flags, from, to, name);
      pbvt_track_range((void *)from, to - from, prot);
      continue;
    }

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

  // TODO: Calculate this based on size of executable memory
  ctx->bitmap = pbvt_calloc(0x1000, sizeof(uint8_t));
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
  // PSB period: expect every 2**(value+11) bytes
  attr.config |= 0 << 24;

  attr.disabled = 0;

  int pfd = syscall(SYS_perf_event_open, &attr, ctx->ppid, -1, -1, 0);
  if (pfd < 0)
    xperror("SYS_perf_event_open");

  struct perf_event_mmap_page *header;
  void *base, *data, *aux;
  UNUSED(data);
  int n = 0, m = 32; // data size, aux size

  base = mmap(NULL, (1 + 2 * n) * PAGE_SIZE, PROT_WRITE, MAP_SHARED, pfd, 0);
  if (base == MAP_FAILED)
    xperror("mmap");

  header = base;
  data = base + header->data_offset;

  header->aux_offset = header->data_offset + header->data_size;
  header->aux_size = (2 * m) * PAGE_SIZE;

  // PROT_READ - circular buffer
  // PROT_READ|PROT_WRITE - linear buffer
  aux = mmap(NULL, header->aux_size, PROT_READ, MAP_SHARED, pfd,
             header->aux_offset);
  if (aux == MAP_FAILED)
    xperror("mmap");

  int xstatus;
  insn_counter = 0;

#ifdef CAPSTONE_DEBUG
  if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
    GDB_PRINTF("cs_open: %s\n", cs_strerror(cs_errno(handle)));
    return -1;
  }
  cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
  tinsn = cs_malloc(handle);
#endif
  uint8_t ptbuf[0x10000];

  xptrace(PTRACE_SYSCALL, ctx->ppid, NULL, NULL);
  waitpid(ctx->ppid, &xstatus, 0);
  if (ioctl(pfd, PERF_EVENT_IOC_DISABLE, 0) < 0)
    xperror("ioctl(PERF_EVENT_IOC_DISABLE)");

  memcpy(ptbuf, aux + header->aux_tail, header->aux_head - header->aux_tail);
  for (int i = 0; i < header->aux_head - header->aux_tail; ++i) {
    printf("%.2x ", ((uint8_t *)ptbuf)[i]);
  }
  printf("\n");

  GDB_PRINTF("%.16lx %.16lx\n", header->aux_tail, header->aux_head);

  struct user_regs_struct xregs = {0};
  xptrace(PTRACE_GETREGS, ctx->ppid, NULL, &xregs);
  // Back up one, since we hit a trap
  GDB_PRINTF("Process ended at rip: 0x%0.16lx\n", xregs.rip - 1);

  process_full_trace(ptbuf, header->aux_head - header->aux_tail, pim, asid);
  header->aux_tail = header->aux_head;

  for (int i = 0; i < 3; ++i) {
    xptrace(PTRACE_SYSCALL, ctx->ppid, NULL, NULL);
    waitpid(ctx->ppid, &xstatus, 0);
  }

  return 0;

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
  // arm.it_interval.tv_sec = 10;
  // arm.it_interval.tv_nsec = 0;
  arm.it_interval.tv_sec = 0;
  arm.it_interval.tv_nsec = 1000 * 1000 * 10;
  arm.it_value.tv_nsec = 0;
  arm.it_value.tv_nsec = 1000 * 1000 * 10;
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

    // Process hit syscall, handle this before our timer in case the process
    // is already stopped on a syscall.
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
      printf("Handle trace!\n");
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
