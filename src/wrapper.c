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

#include "fasthash.h"
#include "gdbstub.h"
#include "pbvt.h"

#define PT_DEBUG

// TODO: Grab binary when first injecting into process
#define APP_NAME "test-app"

#define STACK_SIZE (8 * 1024 * 1024)
#define PROCMAPS_LINE_MAX_LENGTH (PATH_MAX + 100)

#define MIN(a, b) ((a) < (b) ? (a) : (b))

// Saturate X at +/-DERIVE_MAX
#define DERIVE_MAX (0xfefefefe)
#define SAT_INC(x)                                                             \
  do {                                                                         \
    if ((x) + 1 < DERIVE_MAX)                                                  \
      x++;                                                                     \
  } while (0)

// PSB, PSBEND
uint8_t pt_prologue[] = {0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02,
                         0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x23};

void *gdbstub_stk;
pid_t ppid;
int fildes[2];

csh handle;
cs_insn *tinsn;

void sighandler(int signo) {
  UNUSED(signo);
  GDB_PRINTF("pid:%d tid:%d ppid:%d I got the signal!\n", getpid(), gettid(),
             getppid());
  kill(ppid, SIGINT);
  exit(0);
}

void insn_hit_count_inc(gdbctx *ctx, uint64_t ip) {
  for (int i = 0; i < SKETCH_COL; ++i)
    ctx->sketch[i][fasthash64(&ip, sizeof(ip), i) % ctx->sketch_sz]++;
}

uint64_t insn_hit_count_get(gdbctx *ctx, uint64_t ip) {
  uint64_t cnt =
      ctx->sketch[0][fasthash64(&ip, sizeof(ip), 0) % ctx->sketch_sz];
  for (int i = 1; i < SKETCH_COL; ++i) {
    cnt = MIN(cnt,
              ctx->sketch[i][fasthash64(&ip, sizeof(ip), i) % ctx->sketch_sz]);
  }
  return cnt;
}

size_t insn_counter;
int process_block(struct pt_block *block,
                  struct pt_image_section_cache *iscache, uint64_t *fip,
                  gdbctx *ctx) {
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

    insn_hit_count_inc(ctx, insn.ip);

    const uint8_t *code = (uint8_t *)ip;
    uint64_t address = ip;
    size_t sz = 0x10; // max size of x86 insn is 15 bytes
    if (!cs_disasm_iter(handle, &code, &sz, &address, tinsn)) {
      GDB_PRINTF("cs_disasm_iter: %s\n", cs_strerror(cs_errno(handle)));
      break;
    }
    // GDB_PRINTF("0x%.16lx[%c]:\t%s\t%s\n", insn.ip, insn.speculative ? '?' :
    // 'x',
    //            tinsn->mnemonic, tinsn->op_str);
    ip += tinsn->size;
    insn_counter++;
  }

  *fip = ip;

  return 0;
}

int handle_events(struct pt_block_decoder *decoder, int status) {
  while (status & pts_event_pending) {
    struct pt_event event;
    status = pt_blk_event(decoder, &event, sizeof(event));
    if (status < 0)
      break;
  }

  return status;
}

int pt_process_trace(uint8_t *buf, size_t n, gdbctx *ctx) {
  UNUSED(ctx);

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
      pt_image_add_cached(pt_blk_get_image(decoder), ctx->pim, ctx->asid, NULL);
  if (pim_status < 0) {
    GDB_PRINTF("pt_image_add_cached(%d): %s\n", ctx->asid,
               pt_errstr(pim_status));
    exit(-1);
  }

  int wstatus;
  uint64_t fip = 0xdeadbeefdeadbeef;
  for (;;) {
    wstatus = pt_blk_sync_forward(decoder);
    if (wstatus < 0)
      break;

    for (;;) {
      struct pt_block block;
      int errcode;

      wstatus = handle_events(decoder, wstatus);
      if (wstatus < 0)
        break;

      wstatus = pt_blk_next(decoder, &block, sizeof(block));
      errcode = process_block(&block, ctx->pim, &fip, ctx);
      if (wstatus == -pte_eos)
        break;

      if (errcode < 0)
        wstatus = errcode;
      if (wstatus < 0)
        break;
    }
    if (wstatus == -pte_eos)
      break;
    if (wstatus < 0)
      break;
  }

  // GDB_PRINTF("Final ip from decode: 0x%.16lx\n", fip);
  // GDB_PRINTF("Finished processing %d instructions.\n", insn_counter);

  pt_blk_free_decoder(decoder);

  return 0;
}

int pt_init(gdbctx *ctx) {
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

  attr.disabled = 1;

  ctx->pfd = syscall(SYS_perf_event_open, &attr, ctx->ppid, -1, -1, 0);
  if (ctx->pfd < 0)
    xperror("SYS_perf_event_open");

  // TODO: Make sure that we *always* snapshot often enough that we never
  // overfill our aux buffer, otherwise we'll stop dropping samples

  // data size, aux size
  int n = 0, m = 16;

  ctx->base =
      mmap(NULL, (1 + 2 * n) * PAGE_SIZE, PROT_WRITE, MAP_SHARED, ctx->pfd, 0);
  if (ctx->base == MAP_FAILED)
    xperror("mmap");

  ctx->header = ctx->base;
  ctx->data = ctx->base + ctx->header->data_offset;

  ctx->header->aux_offset = ctx->header->data_offset + ctx->header->data_size;
  ctx->header->aux_size = (2 * m) * PAGE_SIZE;

  // PROT_READ - circular buffer
  // PROT_READ|PROT_WRITE - linear buffer
  ctx->aux = mmap(NULL, ctx->header->aux_size, PROT_READ, MAP_SHARED, ctx->pfd,
                  ctx->header->aux_offset);
  if (ctx->aux == MAP_FAILED)
    xperror("mmap");

  if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
    GDB_PRINTF("cs_open: %s\n", cs_strerror(cs_errno(handle)));
    return -1;
  }
  cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
  tinsn = cs_malloc(handle);

  return 0;
}

void pt_update_sketch(gdbctx *ctx) {
  uint8_t ptbuf[0x1000];
  size_t trace_sz = 0;

  if (ctx->header->aux_tail < ctx->header->aux_head) {
    trace_sz = ctx->header->aux_head - ctx->header->aux_tail;
    assert(trace_sz < sizeof(ptbuf));
    memcpy(ptbuf, ctx->aux + ctx->header->aux_tail,
           ctx->header->aux_head - ctx->header->aux_tail);
  } else {
    // Handle wrap-around
    trace_sz = (ctx->header->aux_head) +
               (ctx->header->aux_size - ctx->header->aux_tail);
    assert(trace_sz < sizeof(ptbuf));
    memcpy(ptbuf, ctx->aux + ctx->header->aux_tail,
           ctx->header->aux_size - ctx->header->aux_tail);
    memcpy(ptbuf + (ctx->header->aux_size - ctx->header->aux_tail), ctx->aux,
           ctx->header->aux_head);
  }

  // Check if aux starts with PSB
  if (memcmp(ptbuf, pt_prologue, 16) != 0) {
    memmove(ptbuf + sizeof(pt_prologue), ptbuf, trace_sz);
    memcpy(ptbuf, pt_prologue, sizeof(pt_prologue));
    trace_sz += sizeof(pt_prologue);
  }

#ifdef PT_DEBUG
  GDB_PRINTF("Read from %p to %p\n", ctx->header->aux_tail,
             ctx->header->aux_head);
#endif

  struct user_regs_struct xregs = {0};
  xptrace(PTRACE_GETREGS, ctx->ppid, NULL, &xregs);

  memset(ctx->sketch[0], 0x00, SKETCH_COL * ctx->sketch_sz * sizeof(uint64_t));
  pt_process_trace(ptbuf, trace_sz, ctx);

#ifdef PT_DEBUG
  uint64_t ip = 0x00555555554000 + 0x1227;
  while (ip < 0x00555555554000 + 0x45be + 0x5) {
    const uint8_t *code = (uint8_t *)ip;
    uint64_t address = ip;
    // max size of x86 insn is 15 bytes
    size_t sz = 0x10;
    if (!cs_disasm_iter(handle, &code, &sz, &address, tinsn)) {
      GDB_PRINTF("cs_disasm_iter: %s\n", cs_strerror(cs_errno(handle)));
      break;
    }
    GDB_PRINTF("0x%.16lx[%d]:\t%s\t%s\n", ip, insn_hit_count_get(ctx, ip),
               tinsn->mnemonic, tinsn->op_str);
    ip += tinsn->size;
  }
#endif

  ctx->header->aux_tail = ctx->header->aux_head;
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

  int xstatus;

  for (;;) {
    insn_counter = 0;
    if (ioctl(ctx->pfd, PERF_EVENT_IOC_ENABLE, 0) < 0)
      xperror("ioctl(PERF_EVENT_IOC_ENABLE)");
    xptrace(PTRACE_SYSCALL, ctx->ppid, NULL, NULL);
    waitpid(ctx->ppid, &xstatus, 0);
    if (ioctl(ctx->pfd, PERF_EVENT_IOC_DISABLE, 0) < 0)
      xperror("ioctl(PERF_EVENT_IOC_DISABLE)");

    pt_update_sketch(ctx);
    pbvt_commit();
  }

  return 0;

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
