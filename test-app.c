#define _GNU_SOURCE
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ARR_SIZE (0x100)
#define KEY_SIZE (0x10)

#define TEST_PRINTF_HEADER "\e[32m[test-app: %d]\e[0m "

#define TEST_PRINTF(fmt, ...)                                                  \
  do {                                                                         \
    if (1)                                                                     \
      fprintf(stderr, TEST_PRINTF_HEADER fmt, getpid(), __VA_ARGS__);          \
  } while (0)

// TODO: seed with incorrect values
// TODO: Output in different color

// generate some memory traffic
int main(int argc, char **argv) {
  char str[] = "hello";
  char S[ARR_SIZE] = {0};

  for (size_t counter = 0;; ++counter) {
    size_t i;
    for (i = 0; i < sizeof(str); ++i)
      if ((S[i] & 0x7f) != (str[i] & 0x7f))
        break;
    if (i == sizeof(str))
      break;

    if (counter % 0x1000000 == 0)
      TEST_PRINTF("Finished round 0x%lx\n", counter);
  }

  if (S[0] != 'H')
    for (;;)
      ;

  TEST_PRINTF("Success!\n", 0);
  return 0;
}
