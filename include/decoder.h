#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define CALLSTACK_SZ (0x40)
#define BPOS_SZ (0x20)

typedef enum BB_TYPE {
  BB_INVALID,
  BB_UNCONDITIONAL_JMP,
  BB_CONDITIONAL_JMP,
  BB_INDIRECT_CALL,
  BB_CALL,
  BB_RET,
} BB_TYPE;

typedef struct BasicBlock BasicBlock;

typedef struct BasicBlock {
  BB_TYPE type;
  size_t id;

  // Cold
  uint64_t out[2];
  size_t ninsns;
  uint64_t start;
  uint64_t end;

} BasicBlock;

typedef void (*on_bb_t)(void *, BasicBlock *);

// Partial trace data, hst_sz may not be equal to sz if there are unconditional
// jumps.
typedef struct TransitionTrace {
  BasicBlock **bbs;

  uint64_t tmp;
  size_t tmpsz;

  ssize_t cap;
  ssize_t sz;

  bool invalid; // Indirect calls will invalidate a trace

} TransitionTrace;

typedef struct PTDecoder {
  on_bb_t on_bb;
  void *on_bb_ctx;

  uint64_t *bind_targets;
  size_t bpos_r;
  size_t bpos_w;
  size_t bpos_cap;

  uint64_t last_ip;
  uint64_t ip;

  TransitionTrace *tt;

  BasicBlock *current_bb;

  uint64_t *counters;
  size_t counters_sz;

  // uint64_t callstack[CALLSTACK_SZ];
  // size_t cpos;

  // TODO: Other callbacks?
} PTDecoder;

#define TNT_BUF_SZ (8 * sizeof(uint32_t))

typedef struct TNTCache {
  uint64_t tbuf;
  uint8_t tsz;
  uint32_t *tnt;
  size_t sz;
  size_t cap;
} TNTCache;

int dec_init(PTDecoder *dec);
int dec_decode_trace(PTDecoder *dec, uint8_t *buf, size_t n);
void dec_build_cfg(char *name, PTDecoder *dec, uint64_t ip);
BasicBlock *dec_get_bb(PTDecoder *dec, uint64_t sip);
uint8_t *dec_parse_psb(PTDecoder *dec, uint8_t *trace);

uint8_t *dec_sync_next(PTDecoder *dec, uint8_t *trace, size_t n);
void dec_hit_counters(PTDecoder *dec);

void dec_clear_hit_counters(PTDecoder *dec);
uint64_t dec_hit_count(PTDecoder *dec, BasicBlock *bb);
void dec_set_count(PTDecoder *dec, BasicBlock *bb, uint64_t cnt);