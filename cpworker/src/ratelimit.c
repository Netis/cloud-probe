#include <ratelimit.h>

static double timeval_diff(const struct timeval *a, const struct timeval *b)
{
    long sec = a->tv_sec - b->tv_sec;
    long usec = a->tv_usec - b->tv_usec;
    if (usec < 0)
    {
        sec -= 1;
        usec += 1e6;
    }
    return (double)sec + (double)usec / 1e6;
}

void token_bucket_init(token_bucket_t *tb, uint64_t rate_bps)
{
    tb->rate_bps = rate_bps;
    tb->capacity = rate_bps;
    tb->tokens = rate_bps;
    tb->last_ts.tv_sec = 0;
    tb->last_ts.tv_usec = 0;
}

bool token_bucket_consume(token_bucket_t *tb, size_t bytes, struct timeval ts)
{
    // 判断是否为第一次调用
    if (tb->last_ts.tv_sec > 0)
    {
        double elapsed = timeval_diff(&ts, &tb->last_ts);
        if (elapsed >= 1)
            // 防止 elapsed * tb->rate_bps 乘法溢出
            tb->tokens += tb->rate_bps;
        else if (elapsed > 0)
            tb->tokens += (uint64_t)(elapsed * tb->rate_bps);

        if (tb->tokens > tb->capacity)
            tb->tokens = tb->capacity;
    }

    tb->last_ts = ts;

    uint64_t required = bytes * 8;
    if (tb->tokens >= required)
    {
        tb->tokens -= required;
        return true;
    }

    return false;
}