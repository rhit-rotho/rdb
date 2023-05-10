#define _GNU_SOURCE
#include <capstone/capstone.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "cassert.h"
#include "decoder.h"
#include "rdb_hashtable.h"

#define likely(x) __builtin_expect(x, 1)
#define unlikely(x) __builtin_expect(x, 0)

// Pre-processed basic blocks
RHashTable *bb_cache;
// Insn -> BB map
RHashTable *bb_insn;
// All previously seen positions
RHashTable *bb_seen;

csh handle;
cs_insn *tinsn;

uint8_t PT_PSB[] = {0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82,
                    0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82};
size_t PT_PSB_SZ = sizeof(PT_PSB);

uint8_t PT_PSBEND[] = {0x02, 0x23};
size_t PT_PSBEND_SZ = sizeof(PT_PSBEND);

uint8_t PT_CBR[] = {0x02, 0x03};
size_t PT_CBR_SZ = sizeof(PT_CBR) + 2;

uint8_t PT_LNG_TNT[] = {0x02, 0xa3};
size_t PT_LNG_TNT_SZ = sizeof(PT_LNG_TNT);

uint8_t PT_VMCS[] = {0x02, 0xc8};
size_t PT_VMCS_SZ = sizeof(PT_LNG_TNT) + 5;

uint8_t PT_PAD = 0x00;

uint8_t PT_MODE[] = {0x99};
size_t PT_MODE_SZ = 2;

const char *BB_TYPES[] = {"INVALID", "JMP", "B", "ICALL", "CALL", "RET"};

#define MAX(x, y) ((x) > (y) ? (x) : (y))
#define MIN(x, y) ((x) < (y) ? (x) : (y))

uint64_t murmurhash3_128_to_64(const uint64_t high, const uint64_t low) {
  const uint64_t c1 = 0x87c37b91114253d5ULL;
  const uint64_t c2 = 0x4cf5ad432745937fULL;

  uint64_t h1 = high;
  uint64_t h2 = low;

  h1 *= c1;
  h1 = (h1 << 31) | (h1 >> (64 - 31));
  h1 *= c2;

  h2 *= c2;
  h2 = (h2 << 33) | (h2 >> (64 - 33));
  h2 *= c1;

  h1 ^= h2;
  h1 += h2;

  h1 ^= h1 >> 33;
  h1 *= 0xff51afd7ed558ccdULL;
  h1 ^= h1 >> 33;
  h1 *= 0xc4ceb9fe1a85ec53ULL;
  h1 ^= h1 >> 33;

  return h1;
}

TransitionTrace *trace_init() {
  TransitionTrace *trace = calloc(1, sizeof(TransitionTrace));
  trace->cap = 0x100;
  trace->sz = 0;
  trace->bbs = malloc(trace->cap * sizeof(trace->bbs[0]));
  trace->tmp = 0;
  trace->tmpsz = 0;
  return trace;
}

void trace_push_t(TransitionTrace *trace, uint8_t tnt) {
  trace->tmp <<= 1;
  trace->tmp |= tnt;
  trace->tmpsz += 1;
}

void trace_push(TransitionTrace *tt, BasicBlock *bb) {
  assert(bb != NULL);

  if (tt->sz == tt->cap) {
    tt->cap *= 2;
    tt->bbs = realloc(tt->bbs, tt->cap * sizeof(tt->bbs[0]));
  }

  tt->bbs[tt->sz] = bb;
  tt->sz++;
}

void *bb_alloc(PTDecoder *dec) {
  assert(dec->bb_cnt < 0x1000);
  assert(dec->bb_cnt < dec->counters_sz);
  BasicBlock *bb = calloc(1, sizeof(BasicBlock));
  bb->id = dec->bb_cnt;
  dec->bbs[dec->bb_cnt++] = bb;
  return bb;
}

void hexdump(void *buf, size_t n) {
  printf("%.16lx:\t", buf);
  for (size_t i = 0; i < n; ++i) {
    if ((i % 16 == 0) && (i / 16) > 0)
      printf("\n%.16lx:\t", buf + i);
    printf("%.2x ", ((uint8_t *)buf)[i]);
  }
  printf("\n");
}

uint64_t sext(uint64_t val, uint8_t sign) {
  uint64_t signbit, mask;

  signbit = 1ull << (sign - 1);
  mask = ~0ull << sign;

  return val & signbit ? val | mask : val & ~mask;
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

BasicBlock *dec_get_bb_uncached(PTDecoder *dec, uint64_t sip) {
  // Does our IP already belong to an existing BB? It can't be the start of a
  // basic block, since that would have already been handled by our caller.
  BasicBlock *bb = rht_get(bb_insn, sip);
  if (bb) {
    BasicBlock *nb = bb_alloc(dec);

    uint64_t ip = bb->start;
    size_t ninsns;
    for (ninsns = 0; ip < sip; ++ninsns) {
      const uint8_t *code = (uint8_t *)ip;
      uint64_t address = ip;
      size_t sz = 0x10; // max size of x86 insn is 15 bytes
      if (!cs_disasm_iter(handle, &code, &sz, &address, tinsn)) {
        printf("Broke on invalid\n");
        break;
      }
      ip += tinsn->size;
    }

    nb->ninsns = ninsns;
    nb->start = sip;
    nb->end = bb->end;
    nb->out[0] = bb->out[0];
    nb->out[1] = bb->out[1];
    nb->type = bb->type;

    bb->type = BB_UNCONDITIONAL_JMP;
    bb->ninsns -= nb->ninsns;
    bb->end = sip;
    bb->out[0] = nb->start;

    // TODO: Does this now invalid parts of our trace?
    printf("Split block! %.16lx-%.16lx & %.16lx-%.16lx\n", bb->start, sip, sip,
           nb->end);

    rht_insert(bb_cache, sip, nb);
    return nb;
  }

  bb = bb_alloc(dec);
  bb->start = sip;
  // printf("BB 0x%.16lx:\n", bb->start);

  uint64_t ip = sip;
  size_t ninsns;
  for (ninsns = 1;; ninsns++) {
    const uint8_t *code = (uint8_t *)ip;
    uint64_t address = ip;
    size_t sz = 0x10; // max size of x86 insn is 15 bytes
    if (!cs_disasm_iter(handle, &code, &sz, &address, tinsn)) {
      printf("Broke on invalid\n");
      break;
    }
    // printf("PT: 0x%.16lx:\t%s\t%s\n", tinsn->address, tinsn->mnemonic,
    //        tinsn->op_str);

    if (rht_get(bb_insn, ip)) {
      printf("WARNING: ip 0x%.16lx is already a member of a basic block!\n",
             ip);
    } else {
      rht_insert(bb_insn, ip, bb);
    }

    if (is_control_flow_insn(tinsn))
      break;

    // Transitioning to existing block?
    if (rht_get(bb_insn, ip + tinsn->size)) {
      bb->type = BB_UNCONDITIONAL_JMP;
      bb->end = ip + tinsn->size;
      bb->ninsns = ninsns;
      bb->out[0] = ip + tinsn->size;
      rht_insert(bb_cache, bb->start, bb);
      return bb;
    }

    ip += tinsn->size;
  }

  bb->end = ip + tinsn->size;
  bb->ninsns = ninsns;

  cs_x86 *x86 = &tinsn->detail->x86;
  cs_x86_op *op = &x86->operands[0];

  switch (tinsn->id) {
  case X86_INS_JMP:
    bb->type = BB_UNCONDITIONAL_JMP;
    if (op->type == X86_OP_IMM) {
      bb->out[0] = op->imm;
    } else if (op->type == X86_OP_MEM) {
      bb->type = BB_INDIRECT_CALL;
    } else if (op->type == X86_OP_REG) {
      bb->type = BB_INDIRECT_CALL;
    } else {
      printf("Unsupported jmp!\n");
      abort();
    }
    break;
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
    bb->type = BB_CONDITIONAL_JMP;
    if (op->type == X86_OP_IMM) {
      bb->out[0] = op->imm;
      bb->out[1] = tinsn->address + tinsn->size;
    } else {
      printf("Unsupported call!\n");
      abort();
    }
    break;
  case X86_INS_RET:
    bb->type = BB_RET;
    break;
  case X86_INS_CALL:
    if (op->type == X86_OP_IMM) {
      bb->type = BB_CALL;
      bb->out[0] = op->imm;
    } else if (op->type == X86_OP_REG) {
      bb->type = BB_INDIRECT_CALL;
    } else {
      printf("Unsupported call!\n");
      abort();
    }
    break;
    // ...
  default:
    printf("Unsupported instruction! %d\n", tinsn->id);
    break;
  }

  rht_insert(bb_cache, bb->start, bb);
  return bb;
}

__attribute__((hot)) BasicBlock *dec_get_bb(PTDecoder *dec, uint64_t sip) {
  assert(sip);

  BasicBlock *bb = rht_get(bb_cache, sip);
  if (likely(bb != NULL)) {
    // printf("BB 0x%.16lx:\n", bb->start);
    return bb;
  }

  return dec_get_bb_uncached(dec, sip);
}

BasicBlock *dec_transition_to_next_conditional(PTDecoder *dec) {
  BasicBlock *bb = dec->current_bb;
  for (;;) {
    switch (bb->type) {
    case BB_UNCONDITIONAL_JMP:
      bb = dec_get_bb(dec, bb->out[0]);
      break;
    case BB_CONDITIONAL_JMP:
      return bb;
    case BB_CALL:
      bb = dec_get_bb(dec, bb->out[0]);
      break;
    case BB_RET:
      bb = dec_get_bb(dec, dec->bind_targets[dec->bpos_r]);
      dec->bpos_r = (dec->bpos_r + 1 + BPOS_SZ) % BPOS_SZ;
      break;
    case BB_INDIRECT_CALL:
      assert(0 && "TODO:ICALL");
      assert(dec->bind_targets[dec->bpos_r]);
      bb = dec_get_bb(dec, dec->bind_targets[dec->bpos_r]);
      dec->bpos_r = (dec->bpos_r + 1 + BPOS_SZ) % BPOS_SZ;
      break;
    default:
      __builtin_unreachable();
    }
  }
  return bb;
}

__attribute__((hot)) void dec_flush_tnt(PTDecoder *dec, TransitionTrace *tt) {
  size_t matchsz = 64;
  if (unlikely(dec->current_bb == NULL)) {
    BasicBlock *seen = rht_get(bb_insn, dec->bind_targets[dec->bpos_r]);
    if (seen)
      dec->current_bb = seen;
    else
      dec->current_bb = dec_get_bb(dec, dec->bind_targets[dec->bpos_r]);
    dec->bpos_r++;
    dec->counters[dec->current_bb->id]++;
  }

  if (unlikely(tt->tmpsz == matchsz)) {
    uint64_t key =
        murmurhash3_128_to_64((uint64_t)dec->current_bb->start, tt->tmp);
    size_t i = (size_t)rht_get(bb_seen, key);
    if (i > 0) {
      for (int k = 1; k < 64; ++k)
        dec->counters[tt->bbs[i + k]->id]++;
      dec->current_bb = tt->bbs[i + 63];
      tt->tmp <<= 63;
      tt->tmpsz -= 63;
    } else {
      uint64_t key =
          murmurhash3_128_to_64((uint64_t)dec->current_bb->start, tt->tmp);
      if (rht_get(bb_seen, key) == NULL && tt->sz > 0)
        rht_insert(bb_seen, key, (void *)tt->sz);
    }

    for (size_t i = 0; i < tt->tmpsz; ++i, tt->tmp <<= 1) {
      if ((tt->tmp & (1ull << (8 * sizeof(tt->tmp) - 1))) == 0) {
        trace_push(tt, dec->current_bb);
        BasicBlock *tbb = dec_transition_to_next_conditional(dec);
        dec->current_bb = dec_get_bb(dec, tbb->out[1]);
        dec->counters[dec->current_bb->id]++;
      } else {
        trace_push(tt, dec->current_bb);
        BasicBlock *tbb = dec_transition_to_next_conditional(dec);
        dec->current_bb = dec_get_bb(dec, tbb->out[0]);
        dec->counters[dec->current_bb->id]++;
      }
    }

    tt->tmpsz = 0;
  }
}

void dec_taken(PTDecoder *dec) {
  trace_push_t(dec->tt, 1);
#if 1
  dec_flush_tnt(dec, dec->tt);
#else
  BasicBlock *tbb = dec_transition_to_next_conditional(dec);
  dec->current_bb = dec_get_bb(dec, tbb->out[0]);
  dec->counters[dec->current_bb->id]++;
#endif
}

void dec_not_taken(PTDecoder *dec) {
  trace_push_t(dec->tt, 0);
#if 1
  dec_flush_tnt(dec, dec->tt);
#else
  BasicBlock *tbb = dec_transition_to_next_conditional(dec);
  dec->current_bb = dec_get_bb(dec, tbb->out[1]);
  dec->counters[dec->current_bb->id]++;
#endif
}

uint64_t dec_get_target_ip(uint8_t **trace, uint64_t ip) {
  uint8_t *tp = *trace;
  uint8_t kind = (tp[0] >> 5) & 7;
  uint64_t tip = *(uint64_t *)&tp[1];

  *trace += 1;
  switch (kind) {
  case 0b000:
    *trace += 0;
    return ip;
  case 0b001:
    *trace += 2;
    return (ip & ~0xFFFFull) | (tip & 0xFFFFull);
    break;
  case 0b010:
    *trace += 4;
    return (ip & ~0xFFFFFFFFull) | (tip & 0xFFFFFFFFull);
  case 0b011:
    *trace += 6;
    return sext(tip, 48);
  case 0b100:
    *trace += 6;
    return (ip & ~0xFFFFFFFFFFFFull) | (tip & 0xFFFFFFFFFFFFull);
  case 0b110:
    *trace += 8;
    return tip;
  // case 0b111: // Reserved
  //   break;
  default:
    __builtin_unreachable();
  }
  return ip;
}

RHashTable *processed;

void dec_build_cfg_node(FILE *f, PTDecoder *dec, uint64_t ip) {
  if (rht_get(processed, ip))
    return;

  BasicBlock *bb = rht_get(bb_cache, ip);
  if (!bb) {
    bb = dec_get_bb(dec, ip);
    fprintf(f, "v%.16lx [\n", ip);
    fprintf(f, "		label = \"{%.12lx %s (%ld insns)|(uncalled)}\";\n",
            ip, BB_TYPES[bb->type], bb->ninsns);
    fprintf(f, "];\n");
    rht_insert(processed, ip, (void *)ip);

    return;
  }

  fprintf(f, "v%.16lx [\n", ip);
  fprintf(f, "		label = \"{%.12lx %s (%ld insns)|", ip,
          BB_TYPES[bb->type], bb->ninsns);
  uint64_t sip = ip;
  for (size_t i = 0; i < bb->ninsns; ++i) {
    const uint8_t *code = (uint8_t *)sip;
    uint64_t address = sip;
    size_t sz = 0x10; // max size of x86 insn is 15 bytes
    if (!cs_disasm_iter(handle, &code, &sz, &address, tinsn)) {
      printf("Broke on invalid\n");
      break;
    }
    fprintf(f, "{%s %s}|", tinsn->mnemonic, tinsn->op_str);
    sip += tinsn->size;
  }

  rht_insert(processed, ip, (void *)ip);

  switch (bb->type) {
  case BB_UNCONDITIONAL_JMP:
    fprintf(f, "{<0>x}}\";\n");
    fprintf(f, "];\n");
    fprintf(f, "v%.16lx:0 -> v%.16lx:n\n", ip, bb->out[0]);
    dec_build_cfg_node(f, dec, bb->out[0]);
    break;
  case BB_CONDITIONAL_JMP:
    fprintf(f, "{<0>x|<1>x}}\";\n");
    fprintf(f, "];\n");
    fprintf(f, "v%.16lx:0 -> v%.16lx:n\n", ip, bb->out[0]);
    fprintf(f, "v%.16lx:1 -> v%.16lx:n\n", ip, bb->out[1]);
    dec_build_cfg_node(f, dec, bb->out[0]);
    dec_build_cfg_node(f, dec, bb->out[1]);
    break;
  case BB_CALL:
    fprintf(f, "{<0>ret|<1>branch}}\";\n");
    fprintf(f, "];\n");
    fprintf(f, "v%.16lx:0 -> v%.16lx:n\n", ip, bb->end);
    fprintf(f, "v%.16lx:1 -> v%.16lx:n\n", ip, bb->out[0]);
    dec_build_cfg_node(f, dec, bb->end);
    dec_build_cfg_node(f, dec, bb->out[0]);
    break;
  case BB_INDIRECT_CALL:
    fprintf(f, "{<0>ret|<1>branch (unknown)}}\";\n");
    fprintf(f, "];\n");

    // We don't record all possible branch targets for an indirect call, so...
    fprintf(f, "v%.16lx:0 -> v%.16lx:n\n", ip, bb->end);
    dec_build_cfg_node(f, dec, bb->end);
    break;
  case BB_RET:
    fprintf(f, "{<0>target (unknown)}}\";\n");
    fprintf(f, "];\n");
    break;
  default:
    printf("Unhandled %d.\n", bb->type);
    break;
  }
}

void dec_build_cfg(char *name, PTDecoder *dec, uint64_t ip) {
  processed = rht_create(malloc, calloc, free);
  FILE *f = fopen(name, "w");
  fprintf(f, "digraph {\n");
  fprintf(f, "node[shape=record];\n");
  dec_build_cfg_node(f, dec, ip);
  fprintf(f, "}\n");
  fclose(f);
  rht_free(processed);
}

uint8_t *dec_parse_psb(PTDecoder *dec, uint8_t *trace) {
  for (;;) {
    if (*trace == PT_PAD) {
      trace += 1;
    } else if (memcmp(trace, PT_PSBEND, sizeof(PT_PSBEND)) == 0) {
      trace += PT_PSBEND_SZ;
      break;
    } else if (memcmp(trace, PT_CBR, sizeof(PT_CBR)) == 0) {
      trace += PT_CBR_SZ;
    } else if (memcmp(trace, PT_MODE, sizeof(PT_MODE)) == 0) {
      trace += PT_MODE_SZ;
    } else if (memcmp(trace, PT_VMCS, sizeof(PT_VMCS)) == 0) {
      // TODO: Handle optional on PSB+ (32.4.2.15)
      trace += PT_VMCS_SZ;
    } else if ((trace[0] & 0b11111) == 0b11101) { // FUP
      dec->last_ip = dec_get_target_ip(&trace, dec->last_ip);
    } else {
      printf("Unrecognized packet after PSB! Context: (trace@%.16lx)\n", trace);
      hexdump(trace, 0x20);
      exit(EXIT_FAILURE);
    }
  }
  return trace;
}

uint8_t *dec_sync_next(PTDecoder *dec, uint8_t *trace, size_t n) {
  uint8_t *next = memmem(trace, n, PT_PSB, sizeof(PT_PSB));
  if (next == NULL)
    return trace;

  trace = next;
  trace += PT_PSB_SZ;
  // trace = dec_parse_psb(dec, trace);
  assert(0);
  dec->ip = dec->last_ip;

  return trace;
}

void bin(uint64_t v, size_t n) {
  for (int i = n - 1; i >= 0; --i)
    if (((v >> i) & 0b1) == 1)
      printf("1");
    else
      printf("0");
}

__attribute__((hot)) int dec_decode_trace(PTDecoder *dec, uint8_t *buf,
                                          size_t n) {
  if (n == 0)
    return 0;
  if (!bb_seen)
    bb_seen = rht_create(malloc, calloc, free);

  // hexdump(buf, 0x40);

  // TODO: Could actually unroll several of these, mainly tnt8
  // libxdc does the same, with <3
  static void *dispatch_table[] = {
      &&handle_pt_pad,     // 00000000
      &&handle_pt_tip_pgd, // 00000001
      &&handle_pt_level_2, // 00000010
      &&handle_pt_cyc,     // 00000011
      &&handle_pt_tnt8,    // 00000100
      &&handle_pt_error,   // 00000101
      &&handle_pt_tnt8,    // 00000110
      &&handle_pt_cyc,     // 00000111
      &&handle_pt_tnt8,    // 00001000
      &&handle_pt_error,   // 00001001
      &&handle_pt_tnt8,    // 00001010
      &&handle_pt_cyc,     // 00001011
      &&handle_pt_tnt8,    // 00001100
      &&handle_pt_tip,     // 00001101
      &&handle_pt_tnt8,    // 00001110
      &&handle_pt_cyc,     // 00001111
      &&handle_pt_tnt8,    // 00010000
      &&handle_pt_tip_pge, // 00010001
      &&handle_pt_tnt8,    // 00010010
      &&handle_pt_cyc,     // 00010011
      &&handle_pt_tnt8,    // 00010100
      &&handle_pt_error,   // 00010101
      &&handle_pt_tnt8,    // 00010110
      &&handle_pt_cyc,     // 00010111
      &&handle_pt_tnt8,    // 00011000
      &&handle_pt_tsc,     // 00011001
      &&handle_pt_tnt8,    // 00011010
      &&handle_pt_cyc,     // 00011011
      &&handle_pt_tnt8,    // 00011100
      &&handle_pt_tip_fup, // 00011101
      &&handle_pt_tnt8,    // 00011110
      &&handle_pt_cyc,     // 00011111
      &&handle_pt_tnt8,    // 00100000
      &&handle_pt_tip_pgd, // 00100001
      &&handle_pt_tnt8,    // 00100010
      &&handle_pt_cyc,     // 00100011
      &&handle_pt_tnt8,    // 00100100
      &&handle_pt_error,   // 00100101
      &&handle_pt_tnt8,    // 00100110
      &&handle_pt_cyc,     // 00100111
      &&handle_pt_tnt8,    // 00101000
      &&handle_pt_error,   // 00101001
      &&handle_pt_tnt8,    // 00101010
      &&handle_pt_cyc,     // 00101011
      &&handle_pt_tnt8,    // 00101100
      &&handle_pt_tip,     // 00101101
      &&handle_pt_tnt8,    // 00101110
      &&handle_pt_cyc,     // 00101111
      &&handle_pt_tnt8,    // 00110000
      &&handle_pt_tip_pge, // 00110001
      &&handle_pt_tnt8,    // 00110010
      &&handle_pt_cyc,     // 00110011
      &&handle_pt_tnt8,    // 00110100
      &&handle_pt_error,   // 00110101
      &&handle_pt_tnt8,    // 00110110
      &&handle_pt_cyc,     // 00110111
      &&handle_pt_tnt8,    // 00111000
      &&handle_pt_error,   // 00111001
      &&handle_pt_tnt8,    // 00111010
      &&handle_pt_cyc,     // 00111011
      &&handle_pt_tnt8,    // 00111100
      &&handle_pt_tip_fup, // 00111101
      &&handle_pt_tnt8,    // 00111110
      &&handle_pt_cyc,     // 00111111
      &&handle_pt_tnt8,    // 01000000
      &&handle_pt_tip_pgd, // 01000001
      &&handle_pt_tnt8,    // 01000010
      &&handle_pt_cyc,     // 01000011
      &&handle_pt_tnt8,    // 01000100
      &&handle_pt_error,   // 01000101
      &&handle_pt_tnt8,    // 01000110
      &&handle_pt_cyc,     // 01000111
      &&handle_pt_tnt8,    // 01001000
      &&handle_pt_error,   // 01001001
      &&handle_pt_tnt8,    // 01001010
      &&handle_pt_cyc,     // 01001011
      &&handle_pt_tnt8,    // 01001100
      &&handle_pt_tip,     // 01001101
      &&handle_pt_tnt8,    // 01001110
      &&handle_pt_cyc,     // 01001111
      &&handle_pt_tnt8,    // 01010000
      &&handle_pt_tip_pge, // 01010001
      &&handle_pt_tnt8,    // 01010010
      &&handle_pt_cyc,     // 01010011
      &&handle_pt_tnt8,    // 01010100
      &&handle_pt_exit,    // 01010101
      &&handle_pt_tnt8,    // 01010110
      &&handle_pt_cyc,     // 01010111
      &&handle_pt_tnt8,    // 01011000
      &&handle_pt_mtc,     // 01011001
      &&handle_pt_tnt8,    // 01011010
      &&handle_pt_cyc,     // 01011011
      &&handle_pt_tnt8,    // 01011100
      &&handle_pt_tip_fup, // 01011101
      &&handle_pt_tnt8,    // 01011110
      &&handle_pt_cyc,     // 01011111
      &&handle_pt_tnt8,    // 01100000
      &&handle_pt_tip_pgd, // 01100001
      &&handle_pt_tnt8,    // 01100010
      &&handle_pt_cyc,     // 01100011
      &&handle_pt_tnt8,    // 01100100
      &&handle_pt_error,   // 01100101
      &&handle_pt_tnt8,    // 01100110
      &&handle_pt_cyc,     // 01100111
      &&handle_pt_tnt8,    // 01101000
      &&handle_pt_error,   // 01101001
      &&handle_pt_tnt8,    // 01101010
      &&handle_pt_cyc,     // 01101011
      &&handle_pt_tnt8,    // 01101100
      &&handle_pt_tip,     // 01101101
      &&handle_pt_tnt8,    // 01101110
      &&handle_pt_cyc,     // 01101111
      &&handle_pt_tnt8,    // 01110000
      &&handle_pt_tip_pge, // 01110001
      &&handle_pt_tnt8,    // 01110010
      &&handle_pt_cyc,     // 01110011
      &&handle_pt_tnt8,    // 01110100
      &&handle_pt_error,   // 01110101
      &&handle_pt_tnt8,    // 01110110
      &&handle_pt_cyc,     // 01110111
      &&handle_pt_tnt8,    // 01111000
      &&handle_pt_error,   // 01111001
      &&handle_pt_tnt8,    // 01111010
      &&handle_pt_cyc,     // 01111011
      &&handle_pt_tnt8,    // 01111100
      &&handle_pt_tip_fup, // 01111101
      &&handle_pt_tnt8,    // 01111110
      &&handle_pt_cyc,     // 01111111
      &&handle_pt_tnt8,    // 10000000
      &&handle_pt_tip_pgd, // 10000001
      &&handle_pt_tnt8,    // 10000010
      &&handle_pt_cyc,     // 10000011
      &&handle_pt_tnt8,    // 10000100
      &&handle_pt_error,   // 10000101
      &&handle_pt_tnt8,    // 10000110
      &&handle_pt_cyc,     // 10000111
      &&handle_pt_tnt8,    // 10001000
      &&handle_pt_error,   // 10001001
      &&handle_pt_tnt8,    // 10001010
      &&handle_pt_cyc,     // 10001011
      &&handle_pt_tnt8,    // 10001100
      &&handle_pt_tip,     // 10001101
      &&handle_pt_tnt8,    // 10001110
      &&handle_pt_cyc,     // 10001111
      &&handle_pt_tnt8,    // 10010000
      &&handle_pt_tip_pge, // 10010001
      &&handle_pt_tnt8,    // 10010010
      &&handle_pt_cyc,     // 10010011
      &&handle_pt_tnt8,    // 10010100
      &&handle_pt_error,   // 10010101
      &&handle_pt_tnt8,    // 10010110
      &&handle_pt_cyc,     // 10010111
      &&handle_pt_tnt8,    // 10011000
      &&handle_pt_mode,    // 10011001
      &&handle_pt_tnt8,    // 10011010
      &&handle_pt_cyc,     // 10011011
      &&handle_pt_tnt8,    // 10011100
      &&handle_pt_tip_fup, // 10011101
      &&handle_pt_tnt8,    // 10011110
      &&handle_pt_cyc,     // 10011111
      &&handle_pt_tnt8,    // 10100000
      &&handle_pt_tip_pgd, // 10100001
      &&handle_pt_tnt8,    // 10100010
      &&handle_pt_cyc,     // 10100011
      &&handle_pt_tnt8,    // 10100100
      &&handle_pt_error,   // 10100101
      &&handle_pt_tnt8,    // 10100110
      &&handle_pt_cyc,     // 10100111
      &&handle_pt_tnt8,    // 10101000
      &&handle_pt_error,   // 10101001
      &&handle_pt_tnt8,    // 10101010
      &&handle_pt_cyc,     // 10101011
      &&handle_pt_tnt8,    // 10101100
      &&handle_pt_tip,     // 10101101
      &&handle_pt_tnt8,    // 10101110
      &&handle_pt_cyc,     // 10101111
      &&handle_pt_tnt8,    // 10110000
      &&handle_pt_tip_pge, // 10110001
      &&handle_pt_tnt8,    // 10110010
      &&handle_pt_cyc,     // 10110011
      &&handle_pt_tnt8,    // 10110100
      &&handle_pt_error,   // 10110101
      &&handle_pt_tnt8,    // 10110110
      &&handle_pt_cyc,     // 10110111
      &&handle_pt_tnt8,    // 10111000
      &&handle_pt_error,   // 10111001
      &&handle_pt_tnt8,    // 10111010
      &&handle_pt_cyc,     // 10111011
      &&handle_pt_tnt8,    // 10111100
      &&handle_pt_tip_fup, // 10111101
      &&handle_pt_tnt8,    // 10111110
      &&handle_pt_cyc,     // 10111111
      &&handle_pt_tnt8,    // 11000000
      &&handle_pt_tip_pgd, // 11000001
      &&handle_pt_tnt8,    // 11000010
      &&handle_pt_cyc,     // 11000011
      &&handle_pt_tnt8,    // 11000100
      &&handle_pt_error,   // 11000101
      &&handle_pt_tnt8,    // 11000110
      &&handle_pt_cyc,     // 11000111
      &&handle_pt_tnt8,    // 11001000
      &&handle_pt_error,   // 11001001
      &&handle_pt_tnt8,    // 11001010
      &&handle_pt_cyc,     // 11001011
      &&handle_pt_tnt8,    // 11001100
      &&handle_pt_tip,     // 11001101
      &&handle_pt_tnt8,    // 11001110
      &&handle_pt_cyc,     // 11001111
      &&handle_pt_tnt8,    // 11010000
      &&handle_pt_tip_pge, // 11010001
      &&handle_pt_tnt8,    // 11010010
      &&handle_pt_cyc,     // 11010011
      &&handle_pt_tnt8,    // 11010100
      &&handle_pt_error,   // 11010101
      &&handle_pt_tnt8,    // 11010110
      &&handle_pt_cyc,     // 11010111
      &&handle_pt_tnt8,    // 11011000
      &&handle_pt_error,   // 11011001
      &&handle_pt_tnt8,    // 11011010
      &&handle_pt_cyc,     // 11011011
      &&handle_pt_tnt8,    // 11011100
      &&handle_pt_tip_fup, // 11011101
      &&handle_pt_tnt8,    // 11011110
      &&handle_pt_cyc,     // 11011111
      &&handle_pt_tnt8,    // 11100000
      &&handle_pt_tip_pgd, // 11100001
      &&handle_pt_tnt8,    // 11100010
      &&handle_pt_cyc,     // 11100011
      &&handle_pt_tnt8,    // 11100100
      &&handle_pt_error,   // 11100101
      &&handle_pt_tnt8,    // 11100110
      &&handle_pt_cyc,     // 11100111
      &&handle_pt_tnt8,    // 11101000
      &&handle_pt_error,   // 11101001
      &&handle_pt_tnt8,    // 11101010
      &&handle_pt_cyc,     // 11101011
      &&handle_pt_tnt8,    // 11101100
      &&handle_pt_tip,     // 11101101
      &&handle_pt_tnt8,    // 11101110
      &&handle_pt_cyc,     // 11101111
      &&handle_pt_tnt8,    // 11110000
      &&handle_pt_tip_pge, // 11110001
      &&handle_pt_tnt8,    // 11110010
      &&handle_pt_cyc,     // 11110011
      &&handle_pt_tnt8,    // 11110100
      &&handle_pt_error,   // 11110101
      &&handle_pt_tnt8,    // 11110110
      &&handle_pt_cyc,     // 11110111
      &&handle_pt_tnt8,    // 11111000
      &&handle_pt_error,   // 11111001
      &&handle_pt_tnt8,    // 11111010
      &&handle_pt_cyc,     // 11111011
      &&handle_pt_tnt8,    // 11111100
      &&handle_pt_tip_fup, // 11111101
      &&handle_pt_tnt8,    // 11111110
      &&handle_pt_error,   // 11111111
  };
#define DISPATCH() goto *dispatch_table[p[0]]

  uint8_t *p = buf;
  dec->current_bb = NULL;
  dec->bpos_w = 0;
  dec->bpos_r = 0;
  DISPATCH();

handle_pt_mode:
  p += PT_MODE_SZ;
  DISPATCH();
handle_pt_tip:
  dec->last_ip = dec_get_target_ip(&p, dec->last_ip);
  dec->bind_targets[dec->bpos_w++] = dec->last_ip;
  assert(dec->bpos_w < dec->bpos_cap);
  DISPATCH();
handle_pt_tip_pge:
  dec->last_ip = dec_get_target_ip(&p, dec->last_ip);
  dec->bind_targets[dec->bpos_w++] = dec->last_ip;
  assert(dec->bpos_w < dec->bpos_cap);
  DISPATCH();
handle_pt_tip_pgd:
  dec->last_ip = dec_get_target_ip(&p, dec->last_ip);
  dec->bind_targets[dec->bpos_w++] = dec->last_ip;
  assert(dec->bpos_w < dec->bpos_cap);
  DISPATCH();
handle_pt_tip_fup:
  dec->last_ip = dec_get_target_ip(&p, dec->last_ip);
  dec->bind_targets[dec->bpos_w++] = dec->last_ip;
  assert(dec->bpos_w < dec->bpos_cap);
  DISPATCH();
handle_pt_pad:
  while (likely(*(++p) == PT_PAD))
    ;
  DISPATCH();
handle_pt_level_2:
  switch (p[1]) {
  case 0b00000011: /* CBR */
    p += PT_CBR_SZ;
    DISPATCH();
  case 0b00100011: /* PSBEND */
    p += PT_PSBEND_SZ;
    DISPATCH();
  case 0b01000011: /* PIP */
    assert(0);
    DISPATCH();
  case 0b10000010: /* PSB */
    dec->last_ip = 0;
    p += PT_PSB_SZ;
    DISPATCH();
  case 0b10000011: /* TS  */
    assert(0);
    return -1;
  case 0b10100011: /* LTNT */
    assert(0 && "LTNT");
    DISPATCH();
  case 0b11001000: /* VMCS */
    p += PT_VMCS_SZ;
    DISPATCH();
  case 0b11110011: /* OVF */
    assert(0 && "OVF");
    DISPATCH();
  case 0b11000011: /* MNT */
  case 0b01110011: /* TMA */
  default:
    return -1;
  }
handle_pt_tnt8:
  uint8_t branches = *p;
  uint8_t cnt = 6;
  while ((branches & 0b10000000) == 0) {
    branches <<= 1;
    cnt -= 1;
  }
  branches <<= 1;

  if (1 && likely(dec->tt->tmpsz + cnt < 8 * sizeof(dec->tt->tmp))) {
    dec->tt->tmp <<= cnt;
    dec->tt->tmp |= (branches >> (8 - cnt));
    dec->tt->tmpsz += cnt;
  } else {
    for (int i = 0; i < cnt; ++i, branches <<= 1) {
      if ((branches & (1 << 7)) == 0) {
        dec_not_taken(dec);
      } else {
        dec_taken(dec);
      }
    }
  }
  p++;
  DISPATCH();
handle_pt_mtc:
handle_pt_tsc:
handle_pt_error:
handle_pt_cyc:
  return -1;
handle_pt_exit:

  // Empty remaining TNT
  TransitionTrace *tt = dec->tt;
  // fast-forward to the high bits
  tt->tmp <<= (8 * sizeof(tt->tmp) - tt->tmpsz);
  for (size_t i = 0; i < tt->tmpsz; ++i, tt->tmp <<= 1) {
    if ((tt->tmp & (1ull << (8 * sizeof(tt->tmp) - 1))) == 0) { // Not taken
      BasicBlock *tbb = dec_transition_to_next_conditional(dec);
      dec->current_bb = dec_get_bb(dec, tbb->out[1]);
      dec->counters[dec->current_bb->id]++;
    } else {
      BasicBlock *tbb = dec_transition_to_next_conditional(dec);
      dec->current_bb = dec_get_bb(dec, tbb->out[0]);
      dec->counters[dec->current_bb->id]++;
    }
  }
  tt->tmpsz = 0;
  tt->sz = 0;

  rht_free(bb_seen);
  bb_seen = NULL;

  // TODO: Transition to end of current basic block before snapshotting
  if (dec->current_bb) {
    // dec->counters[dec->current_bb->id]++;
    dec->last_ip = dec->current_bb->start;
    dec->ip = dec->current_bb->end;
  }
  return 0;
}

void dec_clear_hit_counters(PTDecoder *dec) {
  memset(dec->counters, 0x00, sizeof(dec->counters[0]) * dec->counters_sz);
}

uint64_t dec_hit_count(PTDecoder *dec, BasicBlock *bb) {
  return dec->counters[bb->id];
}

void dec_set_count(PTDecoder *dec, BasicBlock *bb, uint64_t cnt) {
  dec->counters[bb->id] = cnt;
}

int dec_init(PTDecoder *dec) {
  if (!bb_cache)
    bb_cache = rht_create(malloc, calloc, free);
  if (!bb_insn)
    bb_insn = rht_create(malloc, calloc, free);
  if (!bb_seen)
    bb_seen = rht_create(malloc, calloc, free);

  if (!handle) {
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
      printf("cs_open: %s\n", cs_strerror(cs_errno(handle)));
      return -1;
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
  }
  if (!tinsn)
    tinsn = cs_malloc(handle);

  dec->bpos_w = 0;
  dec->bpos_r = 0;
  dec->bpos_cap = 0x1000;
  dec->bind_targets = malloc(dec->bpos_cap * sizeof(dec->bind_targets[0]));

  dec->bb_cnt = 0;
  dec->bbs = malloc(sizeof(BasicBlock *) * 0x1000);

  if (dec->counters == NULL) {
    dec->counters_sz = 0x1000;
    dec->counters =
        mmap(NULL, dec->counters_sz * sizeof(uint64_t), PROT_READ | PROT_WRITE,
             MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  }

  dec->tt = trace_init();

  return 0;
}
