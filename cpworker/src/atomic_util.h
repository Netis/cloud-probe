// gcc 4.8 compatible atomic wrappers

#ifndef ATOMIC_UTIL_H
#define ATOMIC_UTIL_H

#define atomic_load_acquire(ptr) __atomic_load_n((ptr), __ATOMIC_ACQUIRE)

#define atomic_load_relaxed(ptr) __atomic_load_n((ptr), __ATOMIC_RELAXED)

#define atomic_store_release(ptr, val) __atomic_store_n((ptr), (val), __ATOMIC_RELEASE)

#define atomic_store_relaxed(ptr, val) __atomic_store_n((ptr), (val), __ATOMIC_RELAXED)

#define atomic_fetch_add_relaxed(ptr, val) __atomic_fetch_add((ptr), (val), __ATOMIC_RELAXED)

#define atomic_fetch_add_release(ptr, val) __atomic_fetch_add((ptr), (val), __ATOMIC_RELEASE)

#define atomic_fetch_sub_relaxed(ptr, val) __atomic_fetch_sub((ptr), (val), __ATOMIC_RELAXED)

#define atomic_fetch_sub_release(ptr, val) __atomic_fetch_sub((ptr), (val), __ATOMIC_RELEASE)

#define atomic_compare_exchange_weak(ptr, expected, desired)                                                           \
    __atomic_compare_exchange_n((ptr), (expected), (desired), 1, /* weak */                                            \
                                __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)

#define atomic_exchange_acq_rel(ptr, val) __atomic_exchange_n((ptr), (val), __ATOMIC_ACQ_REL)

#endif // ATOMIC_UTIL_H