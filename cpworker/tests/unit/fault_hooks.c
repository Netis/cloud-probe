#include "fault_hooks.h"

#include <errno.h>
#include <pthread.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>

void *__real_malloc(size_t size);
void *__real_calloc(size_t nmemb, size_t size);
void *__real_realloc(void *ptr, size_t size);
void __real_free(void *ptr);
int __real_setns(int fd, int nstype);
int __real_pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine)(void *), void *arg);

static long alloc_live;
static long alloc_countdown = -1;
static bool alloc_fired;

static int setns_countdown = -1;

static int thread_delay_ms;
static int threads_finished;

long fault_alloc_live(void) { return __atomic_load_n(&alloc_live, __ATOMIC_SEQ_CST); }

void fault_alloc_fail_nth(long n)
{
    __atomic_store_n(&alloc_fired, false, __ATOMIC_SEQ_CST);
    __atomic_store_n(&alloc_countdown, n, __ATOMIC_SEQ_CST);
}

bool fault_alloc_fired(void) { return __atomic_load_n(&alloc_fired, __ATOMIC_SEQ_CST); }

void fault_setns_fail_nth(int n) { setns_countdown = n; }

void fault_thread_start_delay_ms(int ms) { __atomic_store_n(&thread_delay_ms, ms, __ATOMIC_SEQ_CST); }

int fault_threads_finished(void) { return __atomic_load_n(&threads_finished, __ATOMIC_SEQ_CST); }

/* Allocation failures are armed only from single-threaded test code, so a plain
 * countdown is enough; the counters are atomic because wrapped threads also allocate. */
static bool alloc_should_fail(void)
{
    long left = __atomic_load_n(&alloc_countdown, __ATOMIC_SEQ_CST);
    if (left < 0)
        return false;
    __atomic_store_n(&alloc_countdown, left - 1, __ATOMIC_SEQ_CST);
    if (left > 0)
        return false;
    __atomic_store_n(&alloc_fired, true, __ATOMIC_SEQ_CST);
    return true;
}

void *__wrap_malloc(size_t size)
{
    if (alloc_should_fail())
    {
        errno = ENOMEM;
        return NULL;
    }
    void *p = __real_malloc(size);
    if (p)
        __atomic_add_fetch(&alloc_live, 1, __ATOMIC_SEQ_CST);
    return p;
}

void *__wrap_calloc(size_t nmemb, size_t size)
{
    if (alloc_should_fail())
    {
        errno = ENOMEM;
        return NULL;
    }
    void *p = __real_calloc(nmemb, size);
    if (p)
        __atomic_add_fetch(&alloc_live, 1, __ATOMIC_SEQ_CST);
    return p;
}

void *__wrap_realloc(void *ptr, size_t size)
{
    if (alloc_should_fail())
    {
        errno = ENOMEM;
        return NULL;
    }
    void *p = __real_realloc(ptr, size);
    if (!ptr && p)
        __atomic_add_fetch(&alloc_live, 1, __ATOMIC_SEQ_CST);
    return p;
}

void __wrap_free(void *ptr)
{
    if (ptr)
        __atomic_sub_fetch(&alloc_live, 1, __ATOMIC_SEQ_CST);
    __real_free(ptr);
}

char *__wrap_strdup(const char *s)
{
    size_t len = strlen(s) + 1;
    char *p = __wrap_malloc(len);
    if (p)
        memcpy(p, s, len);
    return p;
}

/* Older glibc (bits/string2.h) turns strdup() into __strdup() when optimizing. */
char *__wrap___strdup(const char *s) { return __wrap_strdup(s); }

int __wrap_setns(int fd, int nstype)
{
    if (setns_countdown < 0)
        return __real_setns(fd, nstype);
    if (setns_countdown-- == 0)
    {
        errno = EPERM;
        return -1;
    }
    return 0;
}

typedef struct
{
    void *(*start_routine)(void *);
    void *arg;
    int delay_ms;
} delayed_start_t;

static void *delayed_start(void *p)
{
    delayed_start_t start = *(delayed_start_t *)p;
    __real_free(p);

    usleep(start.delay_ms * 1000);
    void *ret = start.start_routine(start.arg);
    __atomic_add_fetch(&threads_finished, 1, __ATOMIC_SEQ_CST);
    return ret;
}

int __wrap_pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine)(void *), void *arg)
{
    int delay_ms = __atomic_load_n(&thread_delay_ms, __ATOMIC_SEQ_CST);
    if (delay_ms <= 0)
        return __real_pthread_create(thread, attr, start_routine, arg);

    /* Allocated with the real allocator so the trampoline does not show up in leak counts. */
    delayed_start_t *start = __real_malloc(sizeof(*start));
    if (!start)
        return ENOMEM;
    start->start_routine = start_routine;
    start->arg = arg;
    start->delay_ms = delay_ms;

    int ret = __real_pthread_create(thread, attr, delayed_start, start);
    if (ret != 0)
        __real_free(start);
    return ret;
}
