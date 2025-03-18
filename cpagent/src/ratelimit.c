#include <ratelimit.h>

static double timespec_diff(const struct timespec *a, const struct timespec *b)
{
    long sec = a->tv_sec - b->tv_sec;
    long nsec = a->tv_nsec - b->tv_nsec;
    if (nsec < 0)
    {
        sec -= 1;
        nsec += 1e9;
    }
    return (double)sec + (double)nsec / 1e9;
}

void token_bucket_init(token_bucket_t *tb, uint64_t rate_bps)
{
    tb->rate_bps = rate_bps;
    tb->capacity = rate_bps;
    tb->tokens = rate_bps;
    clock_gettime(CLOCK_MONOTONIC, &tb->last_update);
}

int token_bucket_consume(token_bucket_t *tb, size_t bytes)
{
    uint64_t required = bytes * 8;
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    double elapsed = timespec_diff(&now, &tb->last_update);
    uint64_t new_tokens = (uint64_t)(elapsed * tb->rate_bps);
    tb->tokens += new_tokens;
    if (tb->tokens > tb->capacity)
        tb->tokens = tb->capacity;

    tb->last_update = now;

    if (tb->tokens >= required)
    {
        tb->tokens -= required;
        return 0;
    }

    return -1;
}