#pragma once

#include <errno.h>
#include <stdint.h>
#include <unistd.h>

#define UNUSED(x) (void)(x)

#define SKETCH_COL (4)

#define MIN(a, b) ((a) < (b) ? (a) : (b))

#define GDB_PRINTF_HEADER "\e[33m[gdb: %d, %s:%d]\e[0m "
#define GDB_PRINTF_TRAILER ""

#ifndef NDEBUG
#define GDB_PRINTF(fmt, ...)                                                   \
  do {                                                                         \
    fprintf(stderr, GDB_PRINTF_HEADER fmt GDB_PRINTF_TRAILER, getpid(),        \
            __FILE__, __LINE__, __VA_ARGS__);                                  \
  } while (0)
#else
#define GDB_PRINTF(fmt, ...)                                                   \
  do {                                                                         \
  } while (0)
#endif

#define xioctl(fildes, request, arg)                                           \
  do {                                                                         \
    if (ioctl(fildes, request, arg) == -1) {                                   \
      GDB_PRINTF("%s: %s\n", #request, strerror(errno));                       \
      exit(-1);                                                                \
    }                                                                          \
  } while (0)

// GDB_PRINTF("xptrace(%s)\n", #req);
#define xptrace(req, pid, addr, data)                                          \
  do {                                                                         \
    if (ptrace(req, pid, addr, data) == -1) {                                  \
      GDB_PRINTF("%s: %s\n", #req, strerror(errno));                           \
      exit(-1);                                                                \
    }                                                                          \
  } while (0)

#define xperror(x)                                                             \
  do {                                                                         \
    perror(x);                                                                 \
    exit(-1);                                                                  \
  } while (0);

typedef struct CacheEntry {
  uint64_t sip;
  uint64_t fip;
} CacheEntry;

typedef struct Breakpoint {
  uintptr_t ip;
  uint64_t patch;
} Breakpoint;

typedef struct Sketch {
  uint64_t *counters[SKETCH_COL];
  uint64_t sz;
  uint64_t mask;
} Sketch;

typedef struct gdbctx {
  int fd;
  pid_t ppid;
  volatile struct user_regs_struct *regs;
  volatile struct user_fpregs_struct *fpregs;
  int stopped;

  int timerfd;

  Sketch sketch;
  size_t *insn_count;
  size_t *bb_count;

  pthread_t pt_thread;
  uint8_t pt_running;

  struct perf_event_mmap_page *header;
  void *base, *data, *aux;
  int pfd;

  struct pt_image *image;

  Breakpoint bps[0x20];
  size_t bps_sz;
} gdbctx;

void sketch_init(Sketch *sketch);

void breakpoint_add(gdbctx *ctx, Breakpoint *bp);
void breakpoint_del(gdbctx *ctx, Breakpoint *bp);

uint8_t gdb_checksum(char *c, size_t n);
void gdb_arm_timer(gdbctx *ctx);
void gdb_disarm_timer(gdbctx *ctx);

void gdb_save_state(gdbctx *ctx);
void gdb_pause(gdbctx *ctx);
void gdb_continue(gdbctx *ctx);

void gdb_send_empty(gdbctx *ctx);
void gdb_send_packet(gdbctx *ctx, char *data);
void gdb_send_packet_bytes(gdbctx *ctx, char *data, size_t n);

void gdb_handle_packet(gdbctx *ctx, char *buf, size_t n);
void gdb_handle_b_commands(gdbctx *ctx, char *buf, size_t n);
void gdb_handle_c_commands(gdbctx *ctx, char *buf, size_t n);
void gdb_handle_d_set_commands(gdbctx *ctx, char *buf, size_t n);
void gdb_handle_g_commands(gdbctx *ctx, char *buf, size_t n);
void gdb_handle_h_set_commands(gdbctx *ctx, char *buf, size_t n);
void gdb_handle_m_commands(gdbctx *ctx, char *buf, size_t n);
void gdb_handle_m_set_commands(gdbctx *ctx, char *buf, size_t n);
void gdb_handle_p_set_commands(gdbctx *ctx, char *buf, size_t n);
void gdb_handle_q_commands(gdbctx *ctx, char *buf, size_t n);
void gdb_handle_s_commands(gdbctx *ctx, char *buf, size_t n);
void gdb_handle_v_commands(gdbctx *ctx, char *buf, size_t n);
void gdb_handle_z_add_commands(gdbctx *ctx, char *buf, size_t n);
void gdb_handle_z_del_commands(gdbctx *ctx, char *buf, size_t n);
