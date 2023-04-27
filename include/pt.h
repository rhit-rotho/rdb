#pragma once

#include "gdbstub.h"

void hit_count_inc(Sketch *sketch, uint64_t ip);
uint64_t hit_count_get(Sketch *sketch, uint64_t ip);
int pt_process_trace(gdbctx *ctx, uint8_t *buf, size_t n);
int pt_init(gdbctx *ctx);
void pt_update_sketch(gdbctx *ctx);

void pt_build_cfg(gdbctx*ctx, uint64_t addr);