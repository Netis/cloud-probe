#ifndef CPAGENT_OUTPUT_ROTATING_FILE_H
#define CPAGENT_OUTPUT_ROTATING_FILE_H

#include <stdio.h>
#include <time.h>

#include <pcap/pcap.h>

#include "output.h"
#include "output_file.h"
#include "taskconf.h"

typedef struct RotatingFileOptions
{
    char *file_root;
    int max_file_interval;
    int snaplen;
} rotating_file_options_t;

typedef struct RotatingFileOutput
{
    output_base_t base;

    char *file_root;
    int max_file_interval;

    pcap_t *pcap;
    time_t file_time;
    bool dumper_error;
    FILE *fp;
    pcap_dumper_t *dumper;
} rotating_file_output_t;

output_base_t *rotating_file_output_new_from_cfg(TaskConfig *task_cfg, OutputConfig *output_cfg, char *errbuf);
rotating_file_output_t *rotating_file_output_new(rotating_file_options_t opts, char *errbuf);
void rotating_file_output_destory(output_base_t *self);

#endif /* CPAGENT_OUTPUT_ROTATING_FILE_H */