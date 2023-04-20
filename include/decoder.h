#pragma once

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

typedef struct BasicBlock {
  BB_TYPE type;
  size_t ninsns;
  uint64_t start;
  uint64_t end;
  uint64_t out[2];

  // HACK: Calculate this elsewhere
  uint64_t counters[4];
} BasicBlock;

typedef void (*on_bb_t)(void *, BasicBlock *);

typedef struct PTDecoder {
  uint64_t callstack[CALLSTACK_SZ];
  size_t cpos;

  uint64_t bind_targets[BPOS_SZ];
  size_t bpos_r;
  size_t bpos_w;

  uint64_t last_ip;
  uint64_t ip;

  on_bb_t on_bb;
  void *on_bb_ctx;

  // TODO: Other callbacks?
} PTDecoder;

int dec_init(PTDecoder *dec);
int dec_decode_trace(PTDecoder *dec, uint8_t *buf, size_t n);