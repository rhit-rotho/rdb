#include <assert.h>
#include <capstone/capstone.h>
#include <linux/perf_event.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <time.h>

#include "fasthash.h"
#include "mmap_malloc.h"
#include "pt.h"
#include "rdb_hashtable.h"

// #define PT_DEBUG
#define AUX_SIZE (512)

// PSB, PSBEND
const uint8_t PT_PROLOGUE[] = {0x02, 0x82, 0x02, 0x82, 0x02, 0x82,
                               0x02, 0x82, 0x02, 0x82, 0x02, 0x82,
                               0x02, 0x82, 0x02, 0x82, 0x02, 0x23};

csh handle;
cs_insn *tinsn;
RHashTable *bb_cache;
RHashTable *bb_insn;

__attribute__((hot)) inline void hit_count_inc(Sketch *sketch, uint64_t ip) {
  for (int i = 0; i < SKETCH_COL; ++i)
    sketch->counters[i][fasthash64(&ip, sizeof(ip), i) & sketch->mask]++;
}

__attribute__((hot)) inline uint64_t hit_count_get(Sketch *sketch,
                                                   uint64_t ip) {
  uint64_t cnt =
      sketch->counters[0][fasthash64(&ip, sizeof(ip), 0) & sketch->mask];
  for (int i = 1; i < SKETCH_COL; ++i) {
    cnt =
        MIN(cnt,
            sketch->counters[i][fasthash64(&ip, sizeof(ip), i) & sketch->mask]);
  }
  return cnt;
}

inline uint64_t get_jump_target(cs_insn *insn) {
  // for (int i = 0; i < insn->detail->x86.op_count; i++)
  //   if (insn->detail->x86.operands[i].type == X86_OP_IMM)
  //     return insn->detail->x86.operands[i].imm;

  // Non-portable
  return insn->detail->x86.operands[0].imm;
}

bool is_control_flow_insn(cs_insn *insn) {
  switch (insn->id) {
  case X86_INS_JMP:
  case X86_INS_JE:
  case X86_INS_JNE:
  case X86_INS_JA:
  case X86_INS_JAE:
  case X86_INS_JB:
  case X86_INS_JBE:
  case X86_INS_JG:
  case X86_INS_JGE:
  case X86_INS_JL:
  case X86_INS_JLE:
  case X86_INS_CALL:
  case X86_INS_RET:
    return true;
  default:
    return false;
  }
}

// TODO: We need to convert between what Intel PT considers "blocks"
// (instruction flow that can be recovered without any conditionals) to
// "basic blocks" (straight line sequence that doesn't contain any
// intra-block jumps).
int process_block(gdbctx *ctx, struct pt_block *block, uint64_t *fip) {
  uint16_t ninsn;
  uint64_t ip;

  CacheEntry *et = (CacheEntry *)rht_get(bb_cache, block->ip);
  if (et != NULL) {
    // (*ctx->bb_count)++;
    // *fip = et->fip;
    // *ctx->insn_count += block->ninsn;
    // hit_count_inc(&ctx->sketch, block->ip);
    return 0;
  }

  GDB_PRINTF("New BB! 0x%.16lx\n", block->ip);

  et = malloc(sizeof(CacheEntry));
  et->sip = block->ip;
  ip = block->ip;
  for (ninsn = 0; ninsn < block->ninsn; ++ninsn) {
    const uint8_t *code = (uint8_t *)ip;
    uint64_t address = ip;
    size_t sz = 0x10; // max size of x86 insn is 15 bytes
    if (!cs_disasm_iter(handle, &code, &sz, &address, tinsn))
      break;

#ifdef PT_DEBUG
    GDB_PRINTF("PT: 0x%.16lx[", tinsn->address);
    for (int j = 0; j < tinsn->size; ++j)
      printf("%.2x", *(uint8_t *)(j + ip));
    printf("]:\t%s\t%s\n", tinsn->mnemonic, tinsn->op_str);
#endif

    // TODO: At this point BBs must be split, this may be difficult if we end up
    // interrupting the process inside of a large block many times.
    if (rht_get(bb_insn, ip)) {
      // GDB_PRINTF(
      //     "Warning! Instruction %.16lx is already contained in BB: %.16lx\n",
      //     ip, rht_get(bb_insn, ip));
    } else {
      rht_insert(bb_insn, ip, (void *)block->ip);
    }

    if (tinsn->id == X86_INS_JMP)
      ip = get_jump_target(tinsn);
    else
      ip += tinsn->size;
  }

  et->fip = ip;
  rht_insert(bb_cache, et->sip, et);

  GDB_PRINTF("bb: 0x%.16lx (%ld instructions)\n", block->ip, block->ninsn);
  return process_block(ctx, block, fip);
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

#define RADIX 4096
#define NUM_BITS 50

void msd_radix_sort(uint64_t *arr, int64_t left, int64_t right, int64_t exp) {
  if (left >= right || exp < 0) {
    return;
  }

  size_t count[RADIX + 1] = {0};
  bool is_uniform = true;
  uint64_t prev_digit = (arr[left] >> exp) & (RADIX - 1);

  for (int64_t i = left; i <= right; ++i) {
    uint64_t digit = (arr[i] >> exp) & (RADIX - 1);
    count[digit + 1]++;
    if (digit != prev_digit) {
      is_uniform = false;
    }
    prev_digit = digit;
  }

  if (is_uniform)
    return;

  for (size_t i = 1; i < RADIX + 1; ++i)
    count[i] += count[i - 1];

  uint64_t *temp = (uint64_t *)malloc((right - left + 1) * sizeof(uint64_t));
  if (!temp) {
    fprintf(stderr, "Failed to allocate memory for the temporary array.\n");
    exit(EXIT_FAILURE);
  }

  for (int64_t i = left; i <= right; ++i) {
    uint64_t digit = (arr[i] >> exp) & (RADIX - 1);
    temp[count[digit]++] = arr[i];
  }

  for (int64_t i = left; i <= right; ++i) {
    arr[i] = temp[i - left];
  }

  free(temp);

  for (size_t i = 0; i < RADIX; ++i) {
    msd_radix_sort(arr, left + count[i], left + count[i + 1] - 1,
                   exp - NUM_BITS);
  }
}

void approximate_msd_radix_sort(uint64_t *arr, size_t size) {
  msd_radix_sort(arr, 0, size - 1, 64 - NUM_BITS);
}

double get_time() {
  struct timespec tp;
  clock_gettime(CLOCK_REALTIME, &tp);
  return tp.tv_sec + tp.tv_nsec * 1e-9;
}

int pt_process_trace(gdbctx *ctx, uint8_t *buf, size_t n) {
  UNUSED(ctx);

  struct pt_block_decoder *decoder;
  struct pt_config config;

  pt_config_init(&config);
  config.size = sizeof(config);
  config.begin = buf;
  config.end = buf + n;

  double start = get_time();
  // GDB_PRINTF("Starting PT parse...\n", 0);
  printf("Starting PT parse...\n", 0);

  decoder = pt_blk_alloc_decoder(&config);
  int image_status = pt_blk_set_image(decoder, ctx->image);
  if (image_status < 0) {
    GDB_PRINTF("pt_blk_set_image(%p): %s\n", ctx->image,
               pt_errstr(image_status));
    exit(-1);
  }

  int wstatus;
  uint64_t fip = 0xdeadbeefdeadbeef;
  *ctx->insn_count = 0;
  *ctx->bb_count = 0;
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
      errcode = process_block(ctx, &block, &fip);
      if (wstatus == -pte_eos)
        break;

      if (errcode < 0)
        wstatus = errcode;
      if (wstatus < 0)
        break;
    }

    // TODO: Handle error
    if (wstatus == -pte_eos)
      break;
    if (wstatus < 0)
      break;
  }

  printf("Starting PT parse...done, took %lf seconds\n", get_time() - start);
  GDB_PRINTF("Final ip from decode: 0x%.16lx, status: %d (%s)\n", fip, wstatus,
             pt_errstr(-wstatus));

  GDB_PRINTF("Processed %'d instructions (%'d BBs).\n", *ctx->insn_count,
             *ctx->bb_count);

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
  // /sys/bus/event_source/devices/intel_pt/format/cyc
  attr.config |= 0 << 1;
  // /sys/bus/event_source/devices/intel_pt/format/mtc
  attr.config |= 0 << 9;
  // /sys/bus/event_source/devices/intel_pt/format/tsc
  attr.config |= 0 << 10;
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

  if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
    GDB_PRINTF("cs_open: %s\n", cs_strerror(cs_errno(handle)));
    return -1;
  }
  cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
  tinsn = cs_malloc(handle);

  bb_cache = rht_create(mmap_malloc, mmap_calloc, mmap_free);
  bb_insn = rht_create(mmap_malloc, mmap_calloc, mmap_free);

  return 0;
}

uint8_t ptbuf[2 * AUX_SIZE * PAGE_SIZE];

// TODO: Updates to aux_tail must be atomic, we don't actually need to worry so
// much because we know that our process is stopped and perf events have been
// disabled.
void pt_update_sketch(gdbctx *ctx) {
  GDB_PRINTF("> %s\n", __FUNCTION__);

  size_t trace_sz = 0;

  uint64_t aux_head = ctx->header->aux_head;
  asm volatile("" ::: "memory"); // Ensure the memory barrier
  uint64_t aux_tail = ctx->header->aux_tail;

  /* smp_rmb() required as per /usr/include/linux/perf_event.h */
  // rmb();

  if (aux_tail <= aux_head) {
    trace_sz = aux_head - aux_tail;
    assert(trace_sz < sizeof(ptbuf));
    memcpy(ptbuf, ctx->aux + aux_tail, aux_head - aux_tail);
  } else {
    // Handle wrap-around
    trace_sz = (aux_head) + (ctx->header->aux_size - aux_tail);
    assert(trace_sz < sizeof(ptbuf));
    memcpy(ptbuf, ctx->aux + aux_tail, ctx->header->aux_size - aux_tail);
    memcpy(ptbuf + (ctx->header->aux_size - aux_tail), ctx->aux, aux_head);
  }
  asm volatile("" ::: "memory"); // Ensure the memory barrier
  assert(ctx->header->aux_head == aux_head);
  ctx->header->aux_tail = aux_head;

  // Check if aux starts with PSB
  if (memcmp(ptbuf, PT_PROLOGUE, 16) != 0) {
    memmove(ptbuf + sizeof(PT_PROLOGUE), ptbuf, trace_sz);
    memcpy(ptbuf, PT_PROLOGUE, sizeof(PT_PROLOGUE));
    trace_sz += sizeof(PT_PROLOGUE);
  }

  GDB_PRINTF("Read from 0x%.6lx to 0x%.6lx (tot_size: 0x%.6lx)\n", aux_tail,
             aux_head, ctx->header->aux_size);
#ifdef PT_DEBUG
  // GDB_PRINTF("", 0);
  // for (size_t i = 0; i < trace_sz; ++i)
  //   printf("%.2x ", ptbuf[i]);
  // printf("\n");
#endif

  pt_process_trace(ctx, ptbuf, trace_sz);
  GDB_PRINTF("< %s\n", __FUNCTION__);
}
