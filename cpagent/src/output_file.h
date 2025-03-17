#ifndef CPAGENT_OUTPUT_FILE_H
#define CPAGENT_OUTPUT_FILE_H

#include <stdio.h>

#include <pcap/pcap.h>

#include "output.h"
#include "taskconf.h"

typedef struct FileOutput
{
    output_base_t base;

    FILE *fp;
    pcap_dumper_t *dumper;
} file_output_t;

output_base_t *file_output_new_from_cfg(TaskConfig *task_cfg, OutputConfig *output_cfg, char *errbuf);
file_output_t *file_output_new(const char *name, uint32_t snaplen, char *errbuf);
void file_output_destory(output_base_t *self);

#endif /* CPAGENT_OUTPUT_FILE_H */