#define _GNU_SOURCE
#include <capstone/capstone.h>
#include <linux/perf_event.h>
#include <pthread.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <time.h>

#include "cassert.h"
#include "decoder.h"
#include "fasthash.h"
#include "mmap_malloc.h"
#include "pbvt.h"
#include "pt.h"

// #define PT_DEBUG
#define AUX_SIZE (1024)

#define likely(x) __builtin_expect(x, 1)
#define unlikely(x) __builtin_expect(x, 0)

double get_time() {
  struct timespec tp;
  clock_gettime(CLOCK_REALTIME, &tp);
  return tp.tv_sec + tp.tv_nsec * 1e-9;
}

typedef struct PTArgs {
  gdbctx *ctx;
  uint8_t *buf;
  size_t n;
} PTArgs;

PTDecoder *dec;
PTArgs pt_args;

int counter = 0;
int pt_process_trace(gdbctx *ctx, uint8_t *buf, size_t n) {
  UNUSED(ctx);

  // char path[0x100];
  // snprintf(path, sizeof(path), "traces/trace%.2d.out", counter++);
  // printf("%s: 0x%.16lx\n", path, ctx->regs->rip);
  // FILE *f = fopen(path, "w");
  // fwrite(buf, sizeof(buf[0]), n, f);
  // fclose(f);

  double start = get_time();

  ctx->t_insn_count = 0;
  ctx->t_bb_count = 0;

  // GDB_PRINTF("Starting PT parse @ 0x%.16lx...\n", dec->last_ip);
  int ret = dec_decode_trace(dec, buf, n);

  // GDB_PRINTF("Starting PT parse...done, took %lf seconds\n",
  //            get_time() - start);
  // GDB_PRINTF("Final ip from decode: 0x%.16lx, status: %d\n", dec->last_ip,
  // ret);

  // GDB_PRINTF("Processed %'d instructions (%'d BBs).\n", ctx->t_insn_count,
  //            ctx->t_bb_count);

  *ctx->insn_count += ctx->t_insn_count;
  *ctx->bb_count += ctx->t_bb_count;

  return 0;
}

void *pt_fork_func(void *args) {
  PTArgs *a = (PTArgs *)args;
  // printf("%.16lx %.16lx\n", a->buf, a->n);
  // fflush(stdout);
  pt_process_trace(a->ctx, a->buf, a->n);
  return NULL;
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
  // /sys/bus/event_source/devices/intel_pt/format/cyc
  attr.config |= 0 << 1;
  // /sys/bus/event_source/devices/intel_pt/format/mtc
  attr.config |= 0 << 9;
  // /sys/bus/event_source/devices/intel_pt/format/tsc
  attr.config |= 0 << 10;
  // /sys/bus/event_source/devices/intel_pt/format/noretcomp
  attr.config |= 1 << 11;
  // /sys/bus/event_source/devices/intel_pt/format/branch
  attr.config |= 1 << 13;
  // /sys/bus/event_source/devices/intel_pt/format/psb_period
  // PSB period: expect every 2**(value+11) bytes
  attr.config |= 5 << 24;

  attr.disabled = 1;

  ctx->pfd = syscall(SYS_perf_event_open, &attr, ctx->ppid, -1, -1, 0);
  if (ctx->pfd < 0)
    xperror("SYS_perf_event_open");

  // TODO: Make sure that we *always* snapshot often enough that we never
  // overfill our aux buffer, otherwise we'll stop dropping samples

  // data size, aux size
  int n = 0, m = AUX_SIZE;

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

  dec = malloc(sizeof(PTDecoder));
  dec->counters_sz = 0x1000;
  dec->counters = pbvt_calloc(dec->counters_sz, sizeof(uint64_t));
  dec_init(dec);

  return 0;
}

uint64_t pt_hit_count(BasicBlock *bb) { return dec_hit_count(dec, bb); }

void pt_clear_counters(void) { return dec_clear_hit_counters(dec); }

// TODO: Updates to aux_tail must be atomic, we don't actually need to worry so
// much because we know that our process is stopped and perf events have been
// disabled.
void pt_update_counters(gdbctx *ctx) {
  if (ctx->pt_running) {
    GDB_PRINTF("Waiting for PT...\n", 0);
    pthread_join(ctx->pt_thread, NULL);
    ctx->pt_running = 0;
  }

  size_t trace_sz = 0;

  uint64_t aux_head = ctx->header->aux_head;
  asm volatile("" ::: "memory"); // Ensure the memory barrier
  uint64_t aux_tail = ctx->header->aux_tail;

  /* smp_rmb() required as per /usr/include/linux/perf_event.h */
  // rmb();

  uint8_t *mbuf;

  if (aux_tail <= aux_head) {
    trace_sz = aux_head - aux_tail;
    mbuf = malloc(trace_sz * sizeof(mbuf[0]) + 0x10);
    memcpy(mbuf, ctx->aux + aux_tail, aux_head - aux_tail);
  } else {
    // Handle wrap-around
    trace_sz = (aux_head) + (ctx->header->aux_size - aux_tail);
    mbuf = malloc(trace_sz * sizeof(mbuf[0]) + 0x10);
    memcpy(mbuf, ctx->aux + aux_tail, ctx->header->aux_size - aux_tail);
    memcpy(mbuf + (ctx->header->aux_size - aux_tail), ctx->aux, aux_head);
  }
  asm volatile("" ::: "memory"); // Ensure the memory barrier
  assert(ctx->header->aux_head == aux_head);
  ctx->header->aux_tail = aux_head;

  GDB_PRINTF(
      "Read from 0x%.6lx to 0x%.6lx (trace: 0x%.6lx, tot_size: 0x%.6lx)\n",
      aux_tail, aux_head, trace_sz, ctx->header->aux_size);
#ifdef PT_DEBUG
  // GDB_PRINTF("", 0);
  // for (size_t i = 0; i < trace_sz; ++i)
  //   printf("%.2x ", ptbuf[i]);
  // printf("\n");
#endif

  pt_args.ctx = ctx;
  pt_args.buf = mbuf;
  mbuf[trace_sz] = 0x55;
  pt_args.n = trace_sz;

  pthread_attr_t pattr;
  pthread_attr_init(&pattr);

  int target_core = 0; // Set the target core number here (e.g., core 1)
  cpu_set_t cpuset;

  // Set the CPU affinity for the thread
  CPU_ZERO(&cpuset);
  CPU_SET(target_core, &cpuset);

  if (pthread_attr_setaffinity_np(&pattr, sizeof(cpu_set_t), &cpuset)) {
    perror("pthread_setaffinity_np");
    exit(1);
  }

  // pthread_create(&ctx->pt_thread, &pattr, pt_fork_func, &pt_args);
  // ctx->pt_running = 1;
  pt_process_trace(ctx, mbuf, trace_sz);
  ctx->pt_running = 0;
  free(mbuf);
}

void pt_build_cfg(gdbctx *ctx, uint64_t addr) {
  UNUSED(ctx);
  dec_build_cfg("cfg.dot", dec, addr);
}