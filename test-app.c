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

typedef int (*func)(void);

func f;

int call1() { return 5; }

int call3() { return 10; }

int call2() {
  int result = 0;
  for (int i = 0; i < 0x10; ++i) {
    // result += f();
    result += call1();
  }
  result += call3();
  return result;
}

double get_time() {
  struct timespec tp = {0};
  // clock_gettime(CLOCK_REALTIME, &tp);
  tp.tv_sec = (double)call2();
  return tp.tv_sec + tp.tv_nsec * 1e-9;
}

#include <sys/mman.h>

// TODO: seed with incorrect values
// generate some memory traffic
int main(int argc, char **argv) {
  // volatile uint64_t counterA[0x10] = {0};
  // f = call3;
  double start = get_time();
  TEST_PRINTF("f: %p\n", f);

  uint64_t *counterA =
      mmap(0x13371337000ull, 100 * sizeof(uint64_t), PROT_READ | PROT_WRITE,
           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  if (argc < 2)
    asm("int3");

  char str[] = "hello";
  UNUSED(str);

  // call2();

  // asm("int3");
  uint64_t counter_a;
  for (counter_a = 0; counter_a < 1000000; ++counter_a) {
    counterA[counter_a % 100] = counter_a;

    int other = 0;
    for (uint64_t counter_c = 0; counter_c < 17; ++counter_c) {
      other *= 10;
      other += 15;
    }
    for (uint64_t counter_c = 0; counter_c < 43; ++counter_c) {
      other *= 12;
      other += 16;
    }

    for (uint64_t counter_c = 0; counter_c < 31; ++counter_c) {
      other *= 13;
      other += 17;
    }

    for (uint64_t counter_c = 0; counter_c < 25; ++counter_c) {
      other *= 14;
      other += 18;
    }

    uint64_t val;
    for (uint64_t counter_b = 0; counter_b < 17; ++counter_b) {
      for (uint64_t counter_c = 0; counter_c < 13; ++counter_c) {
        for (uint64_t counter_d = 0; counter_d < 11; ++counter_d) {
          other *= 11;
          other += 17;
        }
        other *= 11;
        other += 17;
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
  }

  asm("int3");
  counterA[0] = 0x03;
  counterA[1] = 0x04;
  counterA[2] = 0x05;

  if (argc < 2) {
    counterA[0] = 0x00;
    counterA[1] = 0x01;
    counterA[2] = 0x02;
    asm("int3");
  }
  double end = get_time();
  double elapsed = end - start;

  TEST_PRINTF("Elapsed: %lf seconds\n", elapsed);
  TEST_PRINTF("Success!\n", 0);
  return 0;
}
