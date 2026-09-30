#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <pcap/pcap.h>

#include "config.h"
#include "errorf.h"
#include "log.h"
#include "output_file.h"
#include "pkt_dir.h"
#include "stats.h"

int file_write_packet(output_base_t *self, const struct pcap_pkthdr *header, const uint8_t *pkt_data, int direct)
{
    file_output_t *output = (file_output_t *)self;

    // A sliced record keeps the wire length in len, as pcap-savefile(5) describes
    struct pcap_pkthdr hdr = *header;
    if (output->slice > 0 && (uint32_t)output->slice < hdr.caplen)
        hdr.caplen = output->slice;

    if (direct == PKT_DIR_UNKNOWN)
    {
        bytes_stats_add(&output->base.stats->direction_drop_bytes, hdr.caplen);
        packets_stats_add(&output->base.stats->direction_drop_packets, 1);
        return -1;
    }

    if (output->rate_limit_mbps > 0)
    {
        if (!token_bucket_consume(&output->throttle, hdr.caplen, hdr.ts))
        {
            bytes_stats_add(&output->base.stats->ratelimit_drop_bytes, hdr.caplen);
            packets_stats_add(&output->base.stats->ratelimit_drop_packets, 1);
            return -1;
        }
    }

    pcap_dump((u_char *)output->dumper, &hdr, pkt_data);
    bytes_stats_add(&output->base.stats->fwd_bytes, hdr.caplen);
    packets_stats_add(&output->base.stats->fwd_packets, 1);
    return 0;
}

int file_output_snaplen(int snaplen, int slice)
{
    if (slice > 0 && slice < snaplen)
        return slice;
    return snaplen;
}

file_output_t *file_output_new(file_options_t opts, output_stats_t *stats, char *errbuf)
{
    FILE *fp = fopen(opts.name, "w+");
    if (!fp)
    {
        error_format(errbuf, "open file %s error: %s", opts.name, strerror(errno));
        return NULL;
    }
    rewind(fp);

    pcap_t *pcap;
    pcap = pcap_open_dead(DLT_EN10MB, file_output_snaplen(opts.snaplen, opts.slice));
    if (!pcap)
    {
        error_format(errbuf, "pcap_open_dead failed");
        fclose(fp);
        return NULL;
    }

    pcap_dumper_t *dumper = pcap_dump_fopen(pcap, fp);
    if (!dumper)
    {
        error_format(errbuf, "pcap_dump_fopen failed: %s", pcap_geterr(pcap));
        fclose(fp);
        pcap_close(pcap);
        return NULL;
    }

    file_output_t *output = (file_output_t *)calloc(1, sizeof(file_output_t));
    if (!output)
    {
        error_format(errbuf, "failed to allocate memory for file_output_t");
        pcap_dump_close(dumper);
        pcap_close(pcap);
        return NULL;
    }

    output->base.send_packet = file_write_packet;
    output->base.heartbeat = NULL;
    output->base.destroy = file_output_destroy;
    output->base.stats = stats;

    if (opts.rate_limit_mbps > 0)
    {
        token_bucket_init(&output->throttle, opts.rate_limit_mbps * 1000000);
    }
    output->rate_limit_mbps = opts.rate_limit_mbps;
    output->slice = opts.slice;

    output->pcap = pcap;
    output->fp = fp;
    output->dumper = dumper;
    return output;
}

output_base_t *file_output_new_from_cfg(TaskConfig *task_cfg, OutputConfig *output_cfg, output_stats_t *stats,
                                        char *errbuf)
{
    file_options_t opts = {
        .name = output_cfg->config.file.name,
        .snaplen = task_capturer_snaplen(task_cfg),
        .slice = output_cfg->slice,
        .rate_limit_mbps = output_cfg->rate_limit_mbps,
    };
    log_info("file output options: name=%s, snaplen=%d, slice=%d, rate_limit_mbps=%" PRIu64, opts.name, opts.snaplen,
             opts.slice, opts.rate_limit_mbps);
    return (output_base_t *)file_output_new(opts, stats, errbuf);
}

void file_output_destroy(output_base_t *self)
{
    if (!self)
        return;

    log_info("call file_output_destroy");
    file_output_t *output = (file_output_t *)self;

    pcap_dump_close(output->dumper);
    pcap_close(output->pcap);
    free(output);
}
