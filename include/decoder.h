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

typedef struct BasicBlock BasicBlock;

typedef struct BasicBlock {
  BB_TYPE type;
  BasicBlock *out_bb[2];

  // Cold
  uint64_t out[2];
  size_t ninsns;
  uint64_t start;
  uint64_t end;

  // 6-bit branch table
  BasicBlock *tbl[1 << 6];

  // HACK: Calculate this elsewhere
  uint64_t counters[4];
} BasicBlock;

typedef void (*on_bb_t)(void *, BasicBlock *);

typedef struct PTDecoder {
  on_bb_t on_bb;
  void *on_bb_ctx;

  uint64_t bind_targets[BPOS_SZ];
  size_t bpos_r;
  size_t bpos_w;

  uint64_t last_ip;
  uint64_t ip;

  BasicBlock *current_bb;

  // uint64_t callstack[CALLSTACK_SZ];
  // size_t cpos;

  // TODO: Other callbacks?
} PTDecoder;

int dec_init(PTDecoder *dec);
int dec_decode_trace(PTDecoder *dec, uint8_t *buf, size_t n);
void dec_build_cfg(char *name, PTDecoder *dec, uint64_t ip);
BasicBlock *dec_get_bb(PTDecoder *dec, uint64_t sip);
uint8_t *dec_parse_psb(PTDecoder *dec, uint8_t *trace);

uint8_t *dec_sync_next(PTDecoder *dec, uint8_t *trace, size_t n);