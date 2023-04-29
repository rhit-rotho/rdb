#include <capstone/capstone.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "cassert.h"
#include "decoder.h"
#include "rdb_hashtable.h"

RHashTable *bb_cache;
RHashTable *bb_insn;

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

char *BB_TYPES[] = {"INVALID", "JMP", "B", "ICALL", "CALL", "RET"};

void hexdump(void *buf, size_t n) {
  printf("%.16lx:\t", buf);
  for (size_t i = 0; i < n; ++i) {
    if ((i % 16 == 0) && (i / 16) > 0)
      printf("\n%.16lx:\t", buf + i);
    printf("%.2x ", ((uint8_t *)buf)[i]);
  }
  printf("\n");
}

inline static uint64_t sext(uint64_t val, uint8_t sign) {
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

BasicBlock *dec_get_bb(PTDecoder *dec, uint64_t sip) {
  assert(sip);
  // printf("----\n");

  BasicBlock *bb = rht_get(bb_cache, sip);
  if (bb) {
    if (dec->on_bb)
      dec->on_bb(dec->on_bb_ctx, bb);
    // printf("BB 0x%.16lx:\n", bb->start);
    return bb;
  }

  if (rht_get(bb_insn, sip)) {
    printf("UNIMPL: About to split!\n");
    abort();

    BasicBlock *bb = rht_get(bb_insn, sip);
    BasicBlock *nb = calloc(1, sizeof(BasicBlock));

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
    bb->out[1] = nb->start;

    printf("Split block! %.16lx-%.16lx & %.16lx-%.16lx\n", bb->start, sip, sip,
           nb->end);

    rht_insert(bb_cache, sip, nb);
    return bb;
  }

  bb = calloc(1, sizeof(BasicBlock));
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
      if (dec->on_bb)
        dec->on_bb(dec->on_bb_ctx, bb);
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
  if (dec->on_bb)
    dec->on_bb(dec->on_bb_ctx, bb);
  return bb;
}

BasicBlock *dec_transition_to_next_conditional(PTDecoder *dec, uint64_t sip) {
  BasicBlock *bb = dec_get_bb(dec, sip);
  for (;;) {
    if (bb->type == BB_CONDITIONAL_JMP) {
      break;
    } else if (bb->type == BB_UNCONDITIONAL_JMP) {
      bb = dec_get_bb(dec, bb->out[0]);
    } else if (bb->type == BB_CALL) {
      // TODO: Compressed RET
      // callstack[cpos] = bb->end;
      // printf(">> %ld: 0x%.16lx\n", cpos, callstack[cpos]);
      // cpos = (cpos + CALLSTACK_SZ + 1) % CALLSTACK_SZ;
      bb = dec_get_bb(dec, bb->out[0]);
    } else if (bb->type == BB_RET) {
      // TODO: Compressed RET
      // cpos = (cpos + CALLSTACK_SZ - 1) % CALLSTACK_SZ;
      // printf("<< %ld: 0x%.16lx\n", cpos, callstack[cpos]);
      // bb = dec_get_bb(dec, callstack[cpos]);
      // bb->out[0] = bind_targets[bpos_r];
      // return bb;
      bb = dec_get_bb(dec, dec->bind_targets[dec->bpos_r]);
      dec->bpos_r = (dec->bpos_r + 1 + BPOS_SZ) % BPOS_SZ;
    } else if (bb->type == BB_INDIRECT_CALL) {
      assert(dec->bind_targets[dec->bpos_r]);
      bb = dec_get_bb(dec, dec->bind_targets[dec->bpos_r]);
      dec->bpos_r = (dec->bpos_r + 1 + BPOS_SZ) % BPOS_SZ;
    } else {
      printf("Unhandled bb type! %d\n", bb->type);
      abort();
    }
  }
  return bb;
}

uint64_t dec_taken(PTDecoder *dec, uint64_t sip) {
  return dec_transition_to_next_conditional(dec, sip)->out[0];
}

uint64_t dec_not_taken(PTDecoder *dec, uint64_t sip) {
  return dec_transition_to_next_conditional(dec, sip)->out[1];
}

static inline uint64_t dec_get_target_ip(uint8_t **trace, uint64_t ip) {
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
    printf("No match!\n");
    return 0;
  }
  return ip;
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

RHashTable *processed;

void dec_build_cfg_node(FILE *f, PTDecoder *dec, uint64_t ip) {
  if (rht_get(processed, ip))
    return;

  BasicBlock *bb = rht_get(bb_cache, ip);
  if (!bb) {
    bb = dec_get_bb(dec, ip);
    fprintf(f, "v%.16lx [\n", ip);
    fprintf(f,
            "		label = \"{%.12lx %s (%ld insns)|(uncalled)}\";\n", ip,
            BB_TYPES[bb->type], bb->ninsns);
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

int dec_decode_trace(PTDecoder *dec, uint8_t *buf, size_t n) {
  uint8_t *trace = buf;
  while (trace < buf + n) {
    if (*trace == PT_PAD) {
      while (*trace == PT_PAD)
        trace += 1;
    } else if (memcmp(trace, PT_PSB, sizeof(PT_PSB)) == 0) {
      trace += PT_PSB_SZ;
      trace = dec_parse_psb(dec, trace);
    } else if (memcmp(trace, PT_CBR, sizeof(PT_CBR)) == 0) {
      trace += PT_CBR_SZ;
    } else if (memcmp(trace, PT_MODE, sizeof(PT_MODE)) == 0) {
      trace += PT_MODE_SZ;
    } else if ((trace[0] & 0b1) == 0b0) { // Short TNT
      // printf("sTNT\n");
      // hexdump(trace, 0x8);
      uint8_t branches = trace[0];
      uint8_t cnt = 6;

      // Find stop bit
      while ((branches & 0b10000000) == 0) {
        branches <<= 1;
        cnt -= 1;
      }
      branches <<= 1;

      for (int i = 0; i < cnt; ++i, branches <<= 1)
        if ((branches & (1ull << 7)) == 0)
          dec->ip = dec_not_taken(dec, dec->ip);
        else
          dec->ip = dec_taken(dec, dec->ip);

      trace += 1;
    } else if ((trace[0] & 0b11111) == 0b10001) { // TIP.PGE
      dec->last_ip = dec_get_target_ip(&trace, dec->last_ip);
    } else if ((trace[0] & 0b11111) == 0b00001) { // TIP.PGD
      dec->last_ip = dec_get_target_ip(&trace, dec->last_ip);
    } else if ((trace[0] & 0b11111) == 0b01101) { // TIP
      dec->last_ip = dec_get_target_ip(&trace, dec->last_ip);
      dec->bind_targets[dec->bpos_w] = dec->last_ip;
      // printf("TIP: %.16lx\n", dec->last_ip);
      // hexdump(trace, 0x8);
      dec->bpos_w = (dec->bpos_w + 1 + BPOS_SZ) % BPOS_SZ;
    } else if ((trace[0] & 0b11111) == 0b11101) { // FUP
      dec->last_ip = dec_get_target_ip(&trace, dec->last_ip);
    } else if (memcmp(trace, PT_LNG_TNT, sizeof(PT_LNG_TNT)) == 0) {
      printf("IMPL: PT_LNG_TNT\n");
      abort();

      uint64_t branches = *(uint64_t *)&trace[0];
      printf("branches: %.16lx ", branches);
      uint64_t cnt = 47;
      while ((branches & (1ull << 63)) == 0) {
        branches <<= 1;
        cnt -= 1;
      }
      branches <<= 1;

      // printf("branches: %.16lx %d\n", branches, cnt);
      for (size_t i = 0; i < cnt; ++i, branches <<= 1)
        if ((branches & (1ull << 63)) == 0)
          dec->ip = dec_not_taken(dec, dec->ip);
        else
          dec->ip = dec_taken(dec, dec->ip);
      trace += 8;
    } else {
      printf("Unrecognized packet! Context (%ld read, %ld bytes "
             "remaining): \n",
             trace - buf, n - (trace - buf));
      hexdump(trace - 0x10, 0x10);
      printf("---HERE---\n");
      hexdump(trace, 0x20);
      return -1;
    }
  }
  return 0;
}

int dec_init(PTDecoder *dec) {
  if (!bb_cache)
    bb_cache = rht_create(malloc, calloc, free);
  if (!bb_insn)
    bb_insn = rht_create(malloc, calloc, free);

  if (!handle) {
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
      printf("cs_open: %s\n", cs_strerror(cs_errno(handle)));
      return -1;
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
  }
  if (!tinsn)
    tinsn = cs_malloc(handle);

  dec->bpos_r = dec->bpos_w;
  return 0;
}
