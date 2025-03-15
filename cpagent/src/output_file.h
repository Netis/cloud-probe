#ifndef CPAGENT_OUTPUT_FILE_H
#define CPAGENT_OUTPUT_FILE_H

#include "output.h"
#include <pcap/pcap.h>
#include <stdio.h>

typedef struct FileOutput
{
    output_base_t base;

    FILE *fp;
    pcap_dumper_t *dumper;
} file_output_t;

file_output_t *new_file_output(const char *name, uint32_t snaplen, char *errbuf);
void free_file_output(output_base_t *output);

#endif /* CPAGENT_OUTPUT_FILE_H */