// TODO: Refactor this into libpbvt implementation

#include <string.h>

#include "cassert.h"
#include "mmap_malloc.h"
#include "rdb_hashtable.h"

#define likely(x) __builtin_expect((x), 1)
#define unlikely(x) __builtin_expect((x), 0)

typedef void *(*use_malloc)(size_t);
typedef void *(*use_calloc)(size_t, size_t);
typedef void (*use_free)(void *);

RHashTable *rht_create(use_malloc tmalloc, use_calloc tcalloc, use_free tfree) {
  RHashTable *ht = tmalloc(sizeof(RHashTable));
  ht->malloc = tmalloc;
  ht->calloc = tcalloc;
  ht->free = tfree;

  ht->cap = RHT_INITIAL_CAP;
  ht->mask = ht->cap - 1;
  ht->size = 0;
  ht->buckets = ht->calloc(ht->cap, sizeof(RHashBucket));

  return ht;
}

void *rht_get(RHashTable *ht, uint64_t key) {
  RHashBucket *bucket = &ht->buckets[key & ht->mask];
  for (size_t i = 0; i < bucket->size; ++i)
    if (bucket->keys[i] == key)
      return bucket->values[i];
  return NULL;
}

void rht_rekey(RHashTable *ht) {
  RHashTable hnt = {0};
  RHashTable *hn = &hnt;
  hn->size = 0;
  hn->cap = ht->cap * 2;
  hn->mask = hn->cap - 1;
  hn->buckets = ht->calloc(hn->cap, sizeof(RHashBucket));

  // reinsert
  for (size_t i = 0; i < ht->cap; ++i) {
    RHashBucket *bucket = &ht->buckets[i];
    for (size_t j = 0; j < bucket->size; ++j) {
      // WARNING: Recursive call, make sure this doesn't reshuffle
      rht_insert(hn, bucket->keys[j], bucket->values[j]);
    }
  }
  ht->free(ht->buckets);
  memcpy(ht, hn, sizeof(RHashTable));
}

// Assumes caller does not try to insert duplicates
int rht_insert(RHashTable *ht, uint64_t key, void *val) {
  assert(!rht_get(ht, key));
  RHashBucket *bucket = &ht->buckets[key & ht->mask];
  while (bucket->size + 1 >= RHT_BUCKET_CAP) {
    rht_rekey(ht);
    bucket = &ht->buckets[key & ht->mask];
  }

  bucket->keys[bucket->size] = key;
  bucket->values[bucket->size] = val;
  bucket->size++;
  ht->size++;

  return 0;
}

void *rht_remove(RHashTable *ht, uint64_t key) {
  RHashBucket *bucket = &ht->buckets[key & ht->mask];
  for (size_t i = 0; i < bucket->size; ++i) {
    if (bucket->keys[i] == key) {
      void *val = bucket->values[i];
      // Shift all elements back one. This should be fast because of our low
      // loading factor.
      for (size_t j = i; j < bucket->size - 1; ++j) {
        bucket->keys[j] = bucket->keys[j + 1];
        bucket->values[j] = bucket->values[j + 1];
      }
      bucket->size--;
      bucket->keys[bucket->size] = 0x5555555555555555;
      bucket->values[bucket->size] = (void *)0x5555555555555555;
      ht->size--;
      return val;
    }
  }
  return NULL;
}

void rht_free(RHashTable *ht) {
  ht->free(ht->buckets);
  ht->free(ht);
}

size_t rht_size(RHashTable *ht) { return ht->size; }