#ifndef CPAGENT_RATELIMIT_H
#define CPAGENT_RATELIMIT_H

#include <stdint.h>
#include <time.h>

typedef struct TokenBucket
{
    uint64_t rate_bps;
    uint64_t capacity;
    uint64_t tokens;
    struct timespec last_update;
} token_bucket_t;

void token_bucket_init(token_bucket_t *tb, uint64_t rate_bps);
int token_bucket_consume(token_bucket_t *tb, size_t bytes);

#endif /* CPAGENT_RATELIMIT_H */