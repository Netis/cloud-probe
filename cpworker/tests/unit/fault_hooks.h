/* Fault-injection hooks for unit tests, installed with the linker's --wrap option.
 *
 * A test binary linked with fault_hooks.c and
 *   -Wl,--wrap=malloc,--wrap=calloc,--wrap=realloc,--wrap=free,--wrap=strdup,--wrap=__strdup
 *   -Wl,--wrap=setns,--wrap=pthread_create
 * routes every call to these functions made from cpworker sources through the hooks below.
 * Calls made inside libc or other shared libraries are not wrapped.
 *
 * With nothing armed, every hook passes straight through to the real function. */

#ifndef CPWORKER_TESTS_FAULT_HOOKS_H
#define CPWORKER_TESTS_FAULT_HOOKS_H

#include <stdbool.h>

/* Allocations (malloc, calloc, realloc, strdup) that have not been freed yet. Compare two
 * readings: allocations made before the first reading are not distinguished. */
long fault_alloc_live(void);

/* Fail the n-th allocation from now (0-based) with ENOMEM. A negative n disarms. */
void fault_alloc_fail_nth(long n);

/* Whether the armed allocation failure has fired since the last fault_alloc_fail_nth(). */
bool fault_alloc_fired(void);

/* Arm setns: the n-th call from now (0-based) fails with EPERM, and every other call
 * returns 0 without changing namespace. A negative n disarms (calls go to the real setns). */
void fault_setns_fail_nth(int n);

/* Make every thread started through pthread_create sleep for ms milliseconds before running
 * its start routine. 0 disables the delay. */
void fault_thread_start_delay_ms(int ms);

/* Number of delayed threads whose start routine has returned. */
int fault_threads_finished(void);

#endif /* CPWORKER_TESTS_FAULT_HOOKS_H */
