#ifndef CPWORKER_OUTPUT_FILE_H
#define CPWORKER_OUTPUT_FILE_H

#include <stdio.h>

#include <pcap/pcap.h>

#include "config.h"
#include "output.h"

typedef struct FileOptions
{
    char *name;
    int snaplen;
    int slice;
} file_options_t;

typedef struct FileOutput
{
    output_base_t base;

    int slice;
    pcap_t *pcap;
    FILE *fp;
    pcap_dumper_t *dumper;
} file_output_t;

output_base_t *file_output_new_from_cfg(TaskConfig *task_cfg, OutputConfig *output_cfg, output_stats_t *stats,
                                        char *errbuf);
file_output_t *file_output_new(file_options_t opts, output_stats_t *stats, char *errbuf);
void file_output_destroy(output_base_t *self);

#endif /* CPWORKER_OUTPUT_FILE_H */