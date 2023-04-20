#define _GNU_SOURCE
#include <assert.h>
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

#include "decoder.h"
#include "fasthash.h"
#include "mmap_malloc.h"
#include "pt.h"
#include "rdb_hashtable.h"

// #define PT_DEBUG
#define AUX_SIZE (256)

__attribute__((hot)) inline void hit_count_inc(Sketch *sketch, uint64_t ip) {
  for (int i = 0; i < SKETCH_COL; ++i)
    sketch->counters[i][fasthash64(&ip, sizeof(ip), i) & sketch->mask]++;
}

__attribute__((hot)) inline uint64_t hit_count_get(Sketch *sketch,
                                                   uint64_t ip) {
  uint64_t cnt =
      sketch->counters[0][fasthash64(&ip, sizeof(ip), 0) & sketch->mask];
  for (int i = 1; i < SKETCH_COL; ++i) {
    cnt =
        MIN(cnt,
            sketch->counters[i][fasthash64(&ip, sizeof(ip), i) & sketch->mask]);
  }
  return cnt;
}

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
pthread_attr_t pattr;

int counter = 0;
int pt_process_trace(gdbctx *ctx, uint8_t *buf, size_t n) {
  UNUSED(ctx);

  // char fname[0x20];
  // snprintf(fname, sizeof(fname), "trace%.2d.out", counter++);
  // FILE *f = fopen(fname, "w");
  // for (size_t i = 0; i < n; ++i) {
  //   fprintf(f, "%c", buf[i]);
  // }
  // fclose(f);

  // usleep(1000 * 1000 * 40);

  double start = get_time();

  // struct user_regs_struct xregs = {0};
  // xptrace(PTRACE_GETREGS, ctx->ppid, NULL, &xregs);

  // TODO: We need these to be configurable to support rewind and replay
  if (!dec->last_ip) {
    dec->last_ip = ctx->regs->rip;
    dec->ip = ctx->regs->rip;
  }

  printf("Starting PT parse @ 0x%.16lx...\n", dec->last_ip);
  int ret = dec_decode_trace(dec, buf, n);

  printf("Starting PT parse...done, took %lf seconds\n", get_time() - start);
  GDB_PRINTF("Final ip from decode: 0x%.16lx, status: %d\n", dec->last_ip, ret);

  GDB_PRINTF("Processed %'d instructions (%'d BBs).\n", *ctx->insn_count,
             *ctx->bb_count);

  return 0;
}

uint64_t empty[] = {0, 0, 0, 0};
void basic_block_callback(void *arg, BasicBlock *bb) {
  gdbctx *ctx = arg;
  (*ctx->bb_count)++;
  (*ctx->insn_count) += bb->ninsns;
  // We don't need any info from the basic block, so just insert the address
  if (unlikely(memcmp(bb->counters, empty, sizeof(empty)) == 0))
    for (int i = 0; i < SKETCH_COL; ++i)
      bb->counters[i] = fasthash64(&bb, sizeof(bb), i) & ctx->sketch.mask;
  for (int i = 0; i < SKETCH_COL; ++i)
    ctx->sketch.counters[i][bb->counters[i]]++;
}

void *pt_fork_func(void *args) {
  PTArgs *a = (PTArgs *)args;
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
  dec_init(dec);
  dec->on_bb = basic_block_callback;
  dec->on_bb_ctx = ctx;

  int core = 11; // Change this to the desired core number

  // Initialize thread attributes
  pthread_attr_init(&pattr);

  // Initialize CPU set
  cpu_set_t cpuset;
  CPU_ZERO(&cpuset);
  CPU_SET(core, &cpuset);

  // Set thread affinity
  int result = pthread_attr_setaffinity_np(&pattr, sizeof(cpu_set_t), &cpuset);
  if (result != 0) {
    perror("pthread_attr_setaffinity_np");
    exit(1);
  }

  return 0;
}

uint8_t ptbuf[2 * AUX_SIZE * PAGE_SIZE];

// TODO: Updates to aux_tail must be atomic, we don't actually need to worry so
// much because we know that our process is stopped and perf events have been
// disabled.
void pt_update_sketch(gdbctx *ctx) {
  GDB_PRINTF("> %s\n", __FUNCTION__);

  size_t trace_sz = 0;

  uint64_t aux_head = ctx->header->aux_head;
  asm volatile("" ::: "memory"); // Ensure the memory barrier
  uint64_t aux_tail = ctx->header->aux_tail;

  /* smp_rmb() required as per /usr/include/linux/perf_event.h */
  // rmb();

  if (aux_tail <= aux_head) {
    trace_sz = aux_head - aux_tail;
    assert(trace_sz < sizeof(ptbuf));
    memcpy(ptbuf, ctx->aux + aux_tail, aux_head - aux_tail);
  } else {
    // Handle wrap-around
    trace_sz = (aux_head) + (ctx->header->aux_size - aux_tail);
    assert(trace_sz < sizeof(ptbuf));
    memcpy(ptbuf, ctx->aux + aux_tail, ctx->header->aux_size - aux_tail);
    memcpy(ptbuf + (ctx->header->aux_size - aux_tail), ctx->aux, aux_head);
  }
  asm volatile("" ::: "memory"); // Ensure the memory barrier
  assert(ctx->header->aux_head == aux_head);
  ctx->header->aux_tail = aux_head;

  GDB_PRINTF("Read from 0x%.6lx to 0x%.6lx (tot_size: 0x%.6lx)\n", aux_tail,
             aux_head, ctx->header->aux_size);
#ifdef PT_DEBUG
  // GDB_PRINTF("", 0);
  // for (size_t i = 0; i < trace_sz; ++i)
  //   printf("%.2x ", ptbuf[i]);
  // printf("\n");
#endif

  if (ctx->pt_running) {
    GDB_PRINTF("Waiting for PT...\n", 0);
    pthread_join(ctx->pt_thread, NULL);
    ctx->pt_running = 0;
  }

  pt_args.ctx = ctx;
  pt_args.buf = ptbuf;
  pt_args.n = trace_sz;

  pthread_create(&ctx->pt_thread, &pattr, pt_fork_func, &pt_args);
  ctx->pt_running = 1;
  // pt_process_trace(ctx, ptbuf, trace_sz);
  // ctx->pt_running = 0;
  GDB_PRINTF("< %s\n", __FUNCTION__);
}
