#pragma once

#include "decoder.h"
#include "gdbstub.h"

#include "atomics.h"

typedef struct {
  void (*function)(void *);
  void *argument;
} Job;

typedef struct {
  Job *jobs;
  size_t cap;
  size_t size;
  size_t head;
  size_t tail;
  AtomicMutex mutex;
  AtomicCondVar cmain;
  AtomicCondVar cwork;
} WorkQueue;

int pt_process_trace(gdbctx *ctx, uint8_t *buf, size_t n);
int pt_init(gdbctx *ctx);
void pt_update_counters(gdbctx *ctx);

void pt_build_cfg(gdbctx *ctx, uint64_t addr);

uint64_t pt_hit_count(BasicBlock *bb);
void pt_clear_counters(void);
void pt_finalize(gdbctx *ctx);
void pt_set_count(BasicBlock *bb, uint64_t cnt);

void pt_get_counts(size_t *bbs_cnt, size_t *insns_cnt);
uint64_t pt_incoming_bbs_hits(BasicBlock *bb, Breakpoint *bps);