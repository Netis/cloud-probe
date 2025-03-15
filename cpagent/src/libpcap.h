#ifndef CPAGENT_LIBPCAP_H
#define CPAGENT_LIBPCAP_H

#include <pcap/pcap.h>

#include "capturer.h"
#include "common.h"
#include "taskconf.h"

typedef struct LibpcapOptions
{
    char *interface;
    int snaplen;
    int timeout_ms;
    int promisc;
    int buffer_size;
    char *bpf_filter;
    char *netns;

    ReqPatternConfig req_pattern;
} libpcap_options_t;

typedef struct LibpcapCapturer
{
    capturer_base_t base;
    req_pattern_t *req_pattern;

    pcap_t *p;
} libpcap_capturer_t;

capturer_base_t *new_libpcap_capture_by_cfg(TaskConfig *task_cfg, char *errbuf);
libpcap_capturer_t *new_libpcap_capturer(libpcap_options_t opts, char *errbuf);
void free_libpcap_capturer(capturer_base_t *capturer);

#endif /* CPAGENT_LIBPCAP_H */