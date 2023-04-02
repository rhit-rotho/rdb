#pragma once

#include <intel-pt.h>

#include "gdbstub.h"

typedef struct WriteBuffer {
  uint64_t writes[SKETCH_COL][0x1000];
  uint64_t sz[SKETCH_COL];
} WriteBuffer;

void hit_count_inc(Sketch *sketch, uint64_t ip);
uint64_t hit_count_get(Sketch *sketch, uint64_t ip);
int process_block(gdbctx *ctx, WriteBuffer *wb, struct pt_block *block,
                  uint64_t *fip);
int handle_events(struct pt_block_decoder *decoder, int status);
int pt_process_trace(gdbctx *ctx, uint8_t *buf, size_t n);
int pt_init(gdbctx *ctx);
void pt_update_sketch(gdbctx *ctx);
