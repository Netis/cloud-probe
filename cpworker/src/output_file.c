#include <errno.h>
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
    if (direct == PKT_DIR_UNKNOWN)
    {
        bytes_stats_add(&output->base.stats->direction_drop_bytes, header->caplen);
        packets_stats_add(&output->base.stats->direction_drop_packets, 1);
        return -1;
    }

    pcap_dump((u_char *)output->dumper, header, pkt_data);
    bytes_stats_add(&output->base.stats->fwd_bytes, header->caplen);
    packets_stats_add(&output->base.stats->fwd_packets, 1);
    return 0;
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
    pcap = pcap_open_dead(DLT_EN10MB, opts.snaplen);
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
    };
    log_info("file output options: name=%s, snaplen=%d, slice=%d", opts.name, opts.snaplen, output_cfg->slice);
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
