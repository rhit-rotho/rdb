#include <assert.h>
#include <capstone/capstone.h>
#include <linux/perf_event.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/user.h>

#include "fasthash.h"
#include "pt.h"

// PSB, PSBEND
const uint8_t PT_PROLOGUE[] = {0x02, 0x82, 0x02, 0x82, 0x02, 0x82,
                               0x02, 0x82, 0x02, 0x82, 0x02, 0x82,
                               0x02, 0x82, 0x02, 0x82, 0x02, 0x23};

csh handle;
cs_insn *tinsn;

void insn_hit_count_inc(gdbctx *ctx, uint64_t ip) {
  for (int i = 0; i < SKETCH_COL; ++i)
    ctx->sketch[i][fasthash64(&ip, sizeof(ip), i) % ctx->sketch_sz]++;
}

uint64_t insn_hit_count_get(gdbctx *ctx, uint64_t ip) {
  uint64_t cnt =
      ctx->sketch[0][fasthash64(&ip, sizeof(ip), 0) % ctx->sketch_sz];
  for (int i = 1; i < SKETCH_COL; ++i) {
    cnt = MIN(cnt,
              ctx->sketch[i][fasthash64(&ip, sizeof(ip), i) % ctx->sketch_sz]);
  }
  return cnt;
}

size_t insn_counter;
int process_block(struct pt_block *block,
                  struct pt_image_section_cache *iscache, uint64_t *fip,
                  gdbctx *ctx) {
  uint16_t ninsn;
  uint64_t ip;

  ip = block->ip;
  for (ninsn = 0; ninsn < block->ninsn; ++ninsn) {
    struct pt_insn insn;

    memset(&insn, 0, sizeof(insn));
    insn.speculative = block->speculative;
    insn.isid = block->isid;
    insn.mode = block->mode;
    insn.ip = ip;

    if (block->truncated && ((ninsn + 1) == block->ninsn)) {
      insn.truncated = 1;
      insn.size = block->size;

      memcpy(insn.raw, block->raw, insn.size);
    } else {
      int size;
      size = pt_iscache_read(iscache, insn.raw, sizeof(insn.raw), insn.isid,
                             insn.ip);
      if (size < 0)
        return size;

      insn.size = (uint8_t)size;
    }

    insn_hit_count_inc(ctx, insn.ip);

    const uint8_t *code = (uint8_t *)ip;
    uint64_t address = ip;
    size_t sz = 0x10; // max size of x86 insn is 15 bytes
    if (!cs_disasm_iter(handle, &code, &sz, &address, tinsn)) {
      GDB_PRINTF("cs_disasm_iter: %s\n", cs_strerror(cs_errno(handle)));
      break;
    }
    // GDB_PRINTF("0x%.16lx[%c]:\t%s\t%s\n", insn.ip, insn.speculative ? '?' :
    // 'x',
    //            tinsn->mnemonic, tinsn->op_str);
    ip += tinsn->size;
    insn_counter++;
  }

  *fip = ip;

  return 0;
}

int handle_events(struct pt_block_decoder *decoder, int status) {
  while (status & pts_event_pending) {
    struct pt_event event;
    status = pt_blk_event(decoder, &event, sizeof(event));
    if (status < 0)
      break;
  }

  return status;
}

int pt_process_trace(uint8_t *buf, size_t n, gdbctx *ctx) {
  UNUSED(ctx);

  struct pt_block_decoder *decoder;
  struct pt_config config;

  memset(&config, 0, sizeof(config));
  config.size = sizeof(config);
  config.begin = buf;
  config.end = buf + n;
  config.decode.callback = NULL;
  config.decode.context = NULL;

  decoder = pt_blk_alloc_decoder(&config);
  int pim_status =
      pt_image_add_cached(pt_blk_get_image(decoder), ctx->pim, ctx->asid, NULL);
  if (pim_status < 0) {
    GDB_PRINTF("pt_image_add_cached(%d): %s\n", ctx->asid,
               pt_errstr(pim_status));
    exit(-1);
  }

  int wstatus;
  uint64_t fip = 0xdeadbeefdeadbeef;
  for (;;) {
    wstatus = pt_blk_sync_forward(decoder);
    if (wstatus < 0)
      break;

    for (;;) {
      struct pt_block block;
      int errcode;

      wstatus = handle_events(decoder, wstatus);
      if (wstatus < 0)
        break;

      wstatus = pt_blk_next(decoder, &block, sizeof(block));
      errcode = process_block(&block, ctx->pim, &fip, ctx);
      if (wstatus == -pte_eos)
        break;

      if (errcode < 0)
        wstatus = errcode;
      if (wstatus < 0)
        break;
    }
    if (wstatus == -pte_eos)
      break;
    if (wstatus < 0)
      break;
  }

  // GDB_PRINTF("Final ip from decode: 0x%.16lx\n", fip);
  // GDB_PRINTF("Finished processing %d instructions.\n", insn_counter);

  pt_blk_free_decoder(decoder);

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
  // /sys/bus/event_source/devices/intel_pt/format/tsc
  attr.config |= 1 << 10;
  // /sys/bus/event_source/devices/intel_pt/format/branch
  attr.config |= 1 << 13;
  // /sys/bus/event_source/devices/intel_pt/format/psb_period
  // PSB period: expect every 2**(value+11) bytes
  attr.config |= 0 << 24;

  attr.disabled = 1;

  ctx->pfd = syscall(SYS_perf_event_open, &attr, ctx->ppid, -1, -1, 0);
  if (ctx->pfd < 0)
    xperror("SYS_perf_event_open");

  // TODO: Make sure that we *always* snapshot often enough that we never
  // overfill our aux buffer, otherwise we'll stop dropping samples

  // data size, aux size
  int n = 0, m = 16;

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

  if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
    GDB_PRINTF("cs_open: %s\n", cs_strerror(cs_errno(handle)));
    return -1;
  }
  cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
  tinsn = cs_malloc(handle);

  return 0;
}

// TODO: Match with aux size in pt_init
uint8_t ptbuf[2 * 16 * PAGE_SIZE];
void pt_update_sketch(gdbctx *ctx) {
  size_t trace_sz = 0;

  if (ctx->header->aux_tail < ctx->header->aux_head) {
    trace_sz = ctx->header->aux_head - ctx->header->aux_tail;
    assert(trace_sz < sizeof(ptbuf));
    memcpy(ptbuf, ctx->aux + ctx->header->aux_tail,
           ctx->header->aux_head - ctx->header->aux_tail);
  } else {
    // Handle wrap-around
    trace_sz = (ctx->header->aux_head) +
               (ctx->header->aux_size - ctx->header->aux_tail);
    assert(trace_sz < sizeof(ptbuf));
    memcpy(ptbuf, ctx->aux + ctx->header->aux_tail,
           ctx->header->aux_size - ctx->header->aux_tail);
    memcpy(ptbuf + (ctx->header->aux_size - ctx->header->aux_tail), ctx->aux,
           ctx->header->aux_head);
  }

  // Check if aux starts with PSB
  if (memcmp(ptbuf, PT_PROLOGUE, 16) != 0) {
    memmove(ptbuf + sizeof(PT_PROLOGUE), ptbuf, trace_sz);
    memcpy(ptbuf, PT_PROLOGUE, sizeof(PT_PROLOGUE));
    trace_sz += sizeof(PT_PROLOGUE);
  }

// #ifdef PT_DEBUG
  GDB_PRINTF("Read from %p to %p\n", ctx->header->aux_tail,
             ctx->header->aux_head);
// #endif

  pt_process_trace(ptbuf, trace_sz, ctx);

#ifdef PT_DEBUG
  uint64_t ip = 0x00555555554000 + 0x1227;
  while (ip < 0x00555555554000 + 0x45be + 0x5) {
    const uint8_t *code = (uint8_t *)ip;
    uint64_t address = ip;
    // max size of x86 insn is 15 bytes
    size_t sz = 0x10;
    if (!cs_disasm_iter(handle, &code, &sz, &address, tinsn)) {
      GDB_PRINTF("cs_disasm_iter: %s\n", cs_strerror(cs_errno(handle)));
      break;
    }
    GDB_PRINTF("0x%.16lx[%d]:\t%s\t%s\n", ip, insn_hit_count_get(ctx, ip),
               tinsn->mnemonic, tinsn->op_str);
    ip += tinsn->size;
  }
#endif

  ctx->header->aux_tail = ctx->header->aux_head;
}
