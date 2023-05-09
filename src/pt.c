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

typedef struct JobArgs {
  gdbctx *ctx;
  uint8_t *buf;
  size_t sz;
} JobArgs;

void process_trace(void *args) {
  JobArgs *jargs = args;
  pt_process_trace(jargs->ctx, jargs->buf, jargs->sz);
  free(jargs->buf);
  free(jargs);
}

void *worker_thread(void *arg) {
  WorkQueue *queue = (WorkQueue *)arg;

  while (1) {
    atomic_mutex_lock(&queue->mutex);
    while (queue->size == 0) {
      atomic_cond_var_signal(&queue->cwork);
      atomic_cond_var_wait(&queue->cmain, &queue->mutex);
    }
    size_t idx = queue->head;
    atomic_mutex_unlock(&queue->mutex);

    Job job = queue->jobs[idx];
    job.function(job.argument);

    atomic_mutex_lock(&queue->mutex);
    queue->head = (queue->head + 1) % queue->cap;
    queue->size--;
    atomic_mutex_unlock(&queue->mutex);
    atomic_cond_var_signal(&queue->cmain);
  }

  return NULL;
}

void submit_job(WorkQueue *queue, void (*function)(void *), void *arg) {
  // GDB_PRINTF("%s\n", __FUNCTION__);
  atomic_mutex_lock(&queue->mutex);

  if (queue->size == queue->cap) {
    int new_capacity = 2 * queue->cap;
    Job *new_jobs = (Job *)realloc(queue->jobs, new_capacity * sizeof(Job));
    if (!new_jobs) {
      fprintf(stderr, "Failed to expand the work queue\n");
      exit(1);
    }
    if (queue->head > 0) {
      memmove(new_jobs + queue->cap, new_jobs, queue->head * sizeof(Job));
      queue->tail += queue->cap;
    }
    queue->jobs = new_jobs;
    queue->cap = new_capacity;
  }

  queue->jobs[queue->tail].function = function;
  queue->jobs[queue->tail].argument = arg;
  queue->tail = (queue->tail + 1) % queue->cap;
  queue->size++;
  atomic_mutex_unlock(&queue->mutex);
  atomic_cond_var_signal(&queue->cmain);
}

void wait_for_jobs(WorkQueue *queue) {
  // GDB_PRINTF("%s\n", __FUNCTION__);
  // usleep(10000);
  atomic_mutex_lock(&queue->mutex);
  // GDB_PRINTF("%s\n", __FUNCTION__);
  // GDB_PRINTF("%s %.16lx %.16lx %.16lx\n", __FUNCTION__, queue->size,
  //  queue->head, queue->tail);
  while (queue->size > 0)
    atomic_cond_var_wait(&queue->cwork, &queue->mutex);
  // GDB_PRINTF("%s\n", __FUNCTION__);
  atomic_mutex_unlock(&queue->mutex);
  // GDB_PRINTF("%s\n", __FUNCTION__);
}

PTDecoder *dec;

// int counter = 0;
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

  WorkQueue *queue = malloc(sizeof(WorkQueue));
  queue->cap = 100;
  queue->jobs = calloc(queue->cap, sizeof(Job));
  queue->size = 0;
  queue->head = 0;
  queue->tail = 0;
  atomic_cond_var_init(&queue->cwork, NULL);
  atomic_cond_var_init(&queue->cmain, NULL);
  atomic_mutex_init(&queue->mutex, NULL);
  ctx->pt_queue = (void *)queue;

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

  pthread_create(&ctx->pt_thread, &pattr, worker_thread, ctx->pt_queue);

  return 0;
}

uint64_t pt_hit_count(BasicBlock *bb) { return dec_hit_count(dec, bb); }

void pt_clear_counters(void) { return dec_clear_hit_counters(dec); }

// TODO: Updates to aux_tail must be atomic, we don't actually need to worry so
// much because we know that our process is stopped and perf events have been
// disabled.
void pt_update_counters(gdbctx *ctx) {
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

  // GDB_PRINTF(
  //     "Read from 0x%.6lx to 0x%.6lx (trace: 0x%.6lx, tot_size: 0x%.6lx)\n",
  //     aux_tail, aux_head, trace_sz, ctx->header->aux_size);
#ifdef PT_DEBUG
  // GDB_PRINTF("", 0);
  // for (size_t i = 0; i < trace_sz; ++i)
  //   printf("%.2x ", ptbuf[i]);
  // printf("\n");
#endif

  mbuf[trace_sz] = 0x55;

#if 1
  JobArgs *args = malloc(sizeof(JobArgs));
  args->ctx = ctx;
  args->buf = mbuf;
  args->sz = trace_sz;
  submit_job((WorkQueue *)ctx->pt_queue, process_trace, args);
#else
  pt_process_trace(ctx, mbuf, trace_sz);
  free(mbuf);
#endif
}

void pt_finalize(gdbctx *ctx) {
  // GDB_PRINTF("%s\n", __FUNCTION__);
  wait_for_jobs((WorkQueue *)ctx->pt_queue);
  assert(((WorkQueue *)ctx->pt_queue)->size == 0);

  WorkQueue *q = (WorkQueue *)ctx->pt_queue;
  atomic_mutex_lock(&q->mutex);
  GDB_PRINTF("%s %.16lx %.16lx %.16lx\n", __FUNCTION__, q->size, q->head,
             q->tail);

  atomic_mutex_unlock(&q->mutex);
}

void pt_set_count(BasicBlock *bb, uint64_t cnt) {
  return dec_set_count(dec, bb, cnt);
}

void pt_build_cfg(gdbctx *ctx, uint64_t addr) {
  UNUSED(ctx);
  dec_build_cfg("cfg.dot", dec, addr);
}
