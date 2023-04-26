#define _GNU_SOURCE
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define ARR_SIZE (0x100)
#define KEY_SIZE (0x10)
#define UNUSED(x) (void)(x)

#define TEST_PRINTF_HEADER "\e[32m[test-app: %d]\e[0m "

#define DEBUG 1

#define TEST_PRINTF(fmt, ...)                                                  \
  do {                                                                         \
    if (DEBUG)                                                                 \
      fprintf(stderr, TEST_PRINTF_HEADER fmt, getpid(), __VA_ARGS__);          \
  } while (0)

void sighandler(int signo) {
  UNUSED(signo);
  TEST_PRINTF("I got the signal!\n", 0);
  exit(0);
}

int call1() { return 5; }

int call2() {
  int result = 0;
  result += call1();
  result += call1();
  return result;
}

double get_time() {
  struct timespec tp = {0};
  // clock_gettime(CLOCK_REALTIME, &tp);
  tp.tv_sec = (double)call2();
  return tp.tv_sec + tp.tv_nsec * 1e-9;
}

// TODO: seed with incorrect values
// generate some memory traffic
int main(int argc, char **argv) {

  double start = get_time();
  if (argc < 2)
    asm("int3");

  char str[] = "hello";
  char S[ARR_SIZE] = {0};
  UNUSED(str);
  UNUSED(S);

  int other = 0;
  for (uint64_t counter_b = 0; counter_b < 0x10000; ++counter_b) {
    for (uint64_t counter_c = 0; counter_c < 0x800; ++counter_c) {
      other *= 11;
      other += 17;
    }
  }

  int val = 0;
  for (uint64_t counter = 0; counter < 0x500000; ++counter) {
    int other = 0;
    for (uint64_t counter_b = 0; counter_b < 0x10; ++counter_b) {
      for (uint64_t counter_c = 0; counter_c < 0x8; ++counter_c) {
        other *= 11;
        other += 17;
      }
    }

    for (uint64_t counter_b = 0; counter_b < 0x20; ++counter_b) {
      for (uint64_t counter_c = 0; counter_c < 0x10; ++counter_c) {
        other *= 11;
        other += 17;
      }
    }

    val += 255;
    val += 15;
    val += 248;
    val += 233;
    val += 142;
    val += 27;
    val += 249;
    val += 127;
    val += 92;
    val += 64;
    val += 70;
    val += 15;
    val += 252;
    val += 40;
    val += 19;
    val += 97;
    val += 59;
    val += 9;
    val += 2;
    val += 217;
    val += 239;
    val += 29;
    val += 248;
    val += 69;
    val += 88;
    val += 141;
    val += 49;
    val += 107;
    val += 220;
    val += 161;
    val += 100;
    val += 8;
  }

  if (argc < 2)
    asm("int3");
  double end = get_time();
  double elapsed = end - start;

  TEST_PRINTF("Elapsed: %lf seconds\n", elapsed);
  TEST_PRINTF("Success!\n", 0);
  return 0;
}
