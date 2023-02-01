#include <errno.h>
#include <stdint.h>
#include <unistd.h>

#define UNUSED(x) (void)(x)

#define GDB_PRINTF_HEADER "\e[33m[gdb: %d, %s:%d]\e[0m "
#define GDB_PRINTF_TRAILER ""

#ifndef DEBUG
#define DEBUG 1
#endif

#define GDB_PRINTF(fmt, ...)                                                   \
  do {                                                                         \
    if (DEBUG)                                                                 \
      fprintf(stderr, GDB_PRINTF_HEADER fmt GDB_PRINTF_TRAILER, getpid(),      \
              __FILE__, __LINE__, __VA_ARGS__);                                \
  } while (0)

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

typedef struct gdbctx {
  int fd;
  pid_t ppid;
  volatile struct user_regs_struct *regs;
  volatile struct user_fpregs_struct *fpregs;
  int stopped;
} gdbctx;

uint8_t gdb_checksum(char *c, size_t n);

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