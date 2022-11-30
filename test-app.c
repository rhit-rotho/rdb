#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define ARR_SIZE (0x100)
#define KEY_SIZE (0x10)

// generate some memory traffic
int main(int argc, char **argv) {
  uint8_t *S = malloc(sizeof(uint8_t) * ARR_SIZE);
  uint8_t key[] = "hello,    world!";

  for (int x = 0;; x++) {
    for (int i = 0; i < ARR_SIZE; ++i)
      S[i] = i & 0xff;

    for (int i = 0; i < ARR_SIZE; ++i) {
      uint8_t j = (j + S[i] + key[i % KEY_SIZE]) % ARR_SIZE;
      S[i] ^= j;
      S[j] ^= i;
      S[j] ^= j;
    }
    if (x % 0x40000 == 0)
      printf("[app: pid:%d tid:%d ppid:%d] Finished round %d\n", getpid(),
             gettid(), getppid(), x);
  }

  // for (int i = 0; i < ARR_SIZE; ++i) {
  //   printf("%x ", S[i]);
  // }
  // printf("\n");
}