#include <stdlib.h>

#include "errorf.h"
#include "log.h"
#include "output_null.h"
#include "pkt_dir.h"
#include "stats.h"

int null_send_packet(output_base_t *self, const struct pcap_pkthdr *header, const uint8_t *pkt_data, int direct)
{
    null_output_t *output = (null_output_t *)self;

    int32_t length = header->caplen;
    if (output->slice > 0 && output->slice < length)
    {
        length = output->slice;
    }

    if (direct == PKT_DIR_UNKNOWN)
    {
        bytes_stats_add(&output->base.stats->direction_drop_bytes, length);
        packets_stats_add(&output->base.stats->direction_drop_packets, 1);
        return -1;
    }

    if (output->rate_limit_mbps > 0)
    {
        if (!token_bucket_consume(&output->throttle, length, header->ts))
        {
            bytes_stats_add(&output->base.stats->ratelimit_drop_bytes, length);
            packets_stats_add(&output->base.stats->ratelimit_drop_packets, 1);
            return -1;
        }
    }
    bytes_stats_add(&output->base.stats->fwd_bytes, length);
    packets_stats_add(&output->base.stats->fwd_packets, 1);
    return 0;
}

null_output_t *null_output_new(null_options_t opts, output_stats_t *stats, char *errbuf)
{
    null_output_t *output = (null_output_t *)calloc(1, sizeof(null_output_t));
    if (!output)
    {
        error_format(errbuf, "failed to allocate memory for null_output_t");
        return NULL;
    }

    output->base.send_packet = null_send_packet;
    output->base.heartbeat = NULL;
    output->base.destroy = null_output_destroy;
    output->base.stats = stats;

    if (opts.rate_limit_mbps > 0)
    {
        token_bucket_init(&output->throttle, opts.rate_limit_mbps * 1000000);
    }
    output->rate_limit_mbps = opts.rate_limit_mbps;
    output->slice = opts.slice;

    return output;
}

output_base_t *null_output_new_from_cfg(TaskConfig *task_cfg, OutputConfig *output_cfg, output_stats_t *stats,
                                        char *errbuf)
{
    null_options_t opts = {
        .rate_limit_mbps = output_cfg->rate_limit_mbps,
        .slice = output_cfg->slice,
    };
    log_info("null output options: rate_limit_mbps=%d, slice=%d", opts.rate_limit_mbps, opts.slice);
    return (output_base_t *)null_output_new(opts, stats, errbuf);
}

void null_output_destroy(output_base_t *self)
{
    if (!self)
        return;

    log_info("call null_output_destroy");
    null_output_t *output = (null_output_t *)self;
    free(output);
}