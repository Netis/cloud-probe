#ifndef CPWORKER_THREAD_UTIL_H
#define CPWORKER_THREAD_UTIL_H

#include "build_config.h"

#if defined(OS_LINUX)
#include <pthread.h>
#endif

static inline void set_thread_name(const char *name)
{
#if defined(OS_LINUX)
    pthread_setname_np(pthread_self(), name);
#endif
}

#endif /* CPWORKER_THREAD_UTIL_H */