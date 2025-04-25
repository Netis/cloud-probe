// clang-format off
#ifndef CPWORKER_QUEUE_H
#define CPWORKER_QUEUE_H

#include <sys/queue.h>

/* Not included in Linux, but are in FreeBSD and friends.
 *
 * This implementation from FreeBSD's sys/queue.h.
 */
#ifndef TAILQ_FOREACH_SAFE
#define TAILQ_FOREACH_SAFE(var, head, field, tvar)                                                                     \
    for ((var) = TAILQ_FIRST((head)); (var) && ((tvar) = TAILQ_NEXT((var), field), 1); (var) = (tvar))
#endif

#endif	/* CPWORKER_QUEUE_H */