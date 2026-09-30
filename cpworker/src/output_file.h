#ifndef CPWORKER_OUTPUT_FILE_H
#define CPWORKER_OUTPUT_FILE_H

#include <stdio.h>

#include <pcap/pcap.h>

#include "config.h"
#include "output.h"
#include "ratelimit.h"

typedef struct FileOptions
{
    char *name;
    int snaplen;
    int slice;
    uint64_t rate_limit_mbps;
} file_options_t;

typedef struct FileOutput
{
    output_base_t base;

    int slice;
    uint64_t rate_limit_mbps;
    token_bucket_t throttle;
    pcap_t *pcap;
    FILE *fp;
    pcap_dumper_t *dumper;
} file_output_t;

output_base_t *file_output_new_from_cfg(TaskConfig *task_cfg, OutputConfig *output_cfg, output_stats_t *stats,
                                        char *errbuf);
file_output_t *file_output_new(file_options_t opts, output_stats_t *stats, char *errbuf);
// Snapshot length for the savefile header: the slice when it truncates below the capture snaplen
int file_output_snaplen(int snaplen, int slice);
void file_output_destroy(output_base_t *self);

#endif /* CPWORKER_OUTPUT_FILE_H */