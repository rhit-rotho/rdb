#pragma once

#include <intel-pt.h>

#include "gdbstub.h"

void insn_hit_count_inc(gdbctx *ctx, uint64_t ip);
uint64_t insn_hit_count_get(gdbctx *ctx, uint64_t ip);
int process_block(struct pt_block *block,
                  struct pt_image_section_cache *iscache, uint64_t *fip,
                  gdbctx *ctx);
int handle_events(struct pt_block_decoder *decoder, int status);
int pt_process_trace(uint8_t *buf, size_t n, gdbctx *ctx);
int pt_init(gdbctx *ctx);
void pt_update_sketch(gdbctx *ctx);
