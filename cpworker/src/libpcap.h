#ifndef CPWORKER_LIBPCAP_H
#define CPWORKER_LIBPCAP_H

#include <time.h>

#include <pcap/pcap.h>

#include "capturer.h"
#include "config.h"
#include "req_pattern.h"

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

    bool drop_stat_started;
    time_t drop_stat_prev_time;
    uint64_t drop_prev_packets;
    uint64_t ifdrop_prev_packets;

} libpcap_capturer_t;

capturer_base_t *libpcap_capture_new_from_cfg(TaskConfig *task_cfg, char *errbuf);
libpcap_capturer_t *libpcap_capturer_new(libpcap_options_t opts, char *errbuf);
void libpcap_capturer_destory(capturer_base_t *capturer);

#endif /* CPWORKER_LIBPCAP_H */