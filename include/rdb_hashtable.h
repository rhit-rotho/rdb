#pragma once

#include <stddef.h>
#include <stdint.h>

// Basic implementation of hash table with bucketing

#define RHT_INITIAL_CAP (0x800)
#define RHT_BUCKET_CAP (0x10)

typedef void *(*use_malloc)(size_t);
typedef void *(*use_calloc)(size_t, size_t);
typedef void (*use_free)(void *);

typedef struct RHashBucket {
  size_t size;
  uint64_t keys[RHT_BUCKET_CAP];
  void *values[RHT_BUCKET_CAP];
} RHashBucket;

typedef struct RHashTable {
  RHashBucket *buckets;
  size_t cap; // power of 2, number of buckets
  size_t size;
  size_t mask;

  use_malloc malloc;
  use_calloc calloc;
  use_free free;
} RHashTable;

// public operations
RHashTable *rht_create(use_malloc malloc, use_calloc calloc, use_free free);
int rht_insert(RHashTable *ht, uint64_t key, void *val);
void *rht_get(RHashTable *ht, uint64_t key);
void *rht_remove(RHashTable *ht, uint64_t key);
void rht_free(RHashTable *ht);
size_t rht_size(RHashTable *ht);