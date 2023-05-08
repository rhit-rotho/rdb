#pragma once

#include "gdbstub.h"
#include "decoder.h"

int pt_process_trace(gdbctx *ctx, uint8_t *buf, size_t n);
int pt_init(gdbctx *ctx);
void pt_update_counters(gdbctx *ctx);

void pt_build_cfg(gdbctx *ctx, uint64_t addr);

uint64_t pt_hit_count(BasicBlock *bb);
void pt_clear_counters(void);