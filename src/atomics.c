#include "atomics.h"

void atomic_mutex_init(AtomicMutex *mtx, void *t) {
  atomic_flag_clear(&mtx->flag);
}

void atomic_mutex_lock(AtomicMutex *mtx) {
  while (atomic_flag_test_and_set(&mtx->flag))
    ; // spin
}

void atomic_mutex_unlock(AtomicMutex *mtx) { atomic_flag_clear(&mtx->flag); }

void atomic_cond_var_init(AtomicCondVar *cv, void *t) {
  atomic_init(&cv->signaled, false);
}

void atomic_cond_var_wait(AtomicCondVar *cv, AtomicMutex *mtx) {
  while (!atomic_load(&cv->signaled)) {
    atomic_mutex_unlock(mtx);
    usleep(1000); // sleep for 1 ms
    atomic_mutex_lock(mtx);
  }
  atomic_store(&cv->signaled, false); // reset the condition variable
}

void atomic_cond_var_signal(AtomicCondVar *cv) {
  atomic_store(&cv->signaled, true);
}
