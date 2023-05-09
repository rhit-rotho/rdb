#pragma once

#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

// Mutex implementation using C11 atomics
typedef struct {
  atomic_flag flag;
} AtomicMutex;

typedef struct {
  atomic_bool signaled;
} AtomicCondVar;

void atomic_mutex_init(AtomicMutex *mtx,void*t);
void atomic_mutex_lock(AtomicMutex *mtx);
void atomic_mutex_unlock(AtomicMutex *mtx);
void atomic_cond_var_init(AtomicCondVar *cv,void*t);
void atomic_cond_var_wait(AtomicCondVar *cv, AtomicMutex *mtx);
void atomic_cond_var_signal(AtomicCondVar *cv);