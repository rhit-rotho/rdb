#define _GNU_SOURCE
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

#include <time.h>
void sighandler(int signo) {
  UNUSED(signo);
  TEST_PRINTF("I got the signal!\n", 0);
  exit(0);
}

// TODO: seed with incorrect values
uint8_t trand[0x100];

#include <time.h>
double get_time() {
  struct timespec tp;
  clock_gettime(CLOCK_REALTIME, &tp);
  return tp.tv_sec + tp.tv_nsec * 1e-9;
}

// generate some memory traffic
int main(int argc, char **argv) {
  // signal(SIGINT, sighandler);

  // srand(time(0));
  srand(0);
  for (int i = 0; i < sizeof(trand) / sizeof(trand[0]); ++i)
    trand[i] = rand();

  if (argc < 2)
    return -1;

  double start = get_time();
  if (argv[1][0] == 'a')
    asm("int3");

  char str[] = "hello";
  char S[ARR_SIZE] = {0};
  UNUSED(str);
  UNUSED(S);

  int a = 0;
  // for (uint64_t counter = 0; counter < 0x10000000; ++counter) {
  for (uint64_t counter = 0; counter < 0x1000; ++counter) {
    if (a % 2 == 0)
      a = trand[a];
    else
      a = trand[a] ^ trand[(a + 1) % 0x100];
  }

  if (argv[1][0] == 'a')
    asm("int3");

  double end = get_time();
  TEST_PRINTF("Elapsed: %lf seconds\n", end - start);
  TEST_PRINTF("Success!\n", 0);
  return 0;
}
