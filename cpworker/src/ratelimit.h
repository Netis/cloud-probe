#ifndef CPWORKER_RATELIMIT_H
#define CPWORKER_RATELIMIT_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/time.h>
#include <time.h>

typedef struct TokenBucket
{
    uint64_t rate_bps;
    uint64_t capacity;
    uint64_t tokens;
    struct timeval last_ts;
} token_bucket_t;

void token_bucket_init(token_bucket_t *tb, uint64_t rate_bps);
bool token_bucket_consume(token_bucket_t *tb, size_t bytes, struct timeval ts);

#endif /* CPWORKER_RATELIMIT_H */