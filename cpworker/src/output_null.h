#ifndef CPWORKER_OUTPUT_NULL_H
#define CPWORKER_OUTPUT_NULL_H

#include "config.h"
#include "output.h"
#include "ratelimit.h"

typedef struct NullOptions
{
    uint64_t rate_limit_mbps;
    int slice;
} null_options_t;

typedef struct NullOutput
{
    output_base_t base;

    uint64_t rate_limit_mbps;
    token_bucket_t throttle;
    int slice;
} null_output_t;

output_base_t *null_output_new_from_cfg(TaskConfig *task_cfg, OutputConfig *output_cfg, output_stats_t *stats,
                                        char *errbuf);
null_output_t *null_output_new(null_options_t opts, output_stats_t *stats, char *errbuf);
void null_output_destroy(output_base_t *self);

#endif /* CPWORKER_OUTPUT_NULL_H */