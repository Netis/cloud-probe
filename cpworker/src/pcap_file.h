#ifndef CPWORKER_PCAP_FILE_H
#define CPWORKER_PCAP_FILE_H

#include "capturer.h"
#include "req_pattern.h"

typedef struct PcapFileOptions
{
    char *file_name;
    char *bpf_filter;

    ReqPatternConfig req_pattern;
} pcap_file_options_t;

typedef struct PcapFileCapturer
{
    capturer_base_t base;

    req_pattern_t *req_pattern;
    pcap_t *p;
    bool eof;
} pcap_file_capturer_t;

capturer_base_t *pcap_file_capture_new_from_cfg(TaskConfig *task_cfg, char *errbuf);
pcap_file_capturer_t *pcap_file_capturer_new(pcap_file_options_t opts, char *errbuf);
void pcap_file_capturer_destory(capturer_base_t *capturer);

#endif /* CPWORKER_PCAP_FILE_H */