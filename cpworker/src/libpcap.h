#ifndef CPWORKER_LIBPCAP_H
#define CPWORKER_LIBPCAP_H

#include <sys/types.h>
#include <time.h>

#include <pcap/pcap.h>

#include "capturer.h"
#include "config.h"
#include "errorf.h"
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

    char *interface;
    char *netns;
    req_pattern_t *req_pattern;
    pcap_t *p;

    bool drop_stat_started;
    time_t drop_stat_prev_time;
    u_int prev_ps_drop;
    u_int prev_ps_ifdrop;

    char pcap_next_error[ERROR_BUFFER_SIZE];

} libpcap_capturer_t;

capturer_base_t *libpcap_capture_new_from_cfg(TasksAllConfig *tasks_cfg, TaskConfig *task_cfg, capture_stats_t *stats,
                                              char *errbuf);
libpcap_capturer_t *libpcap_capturer_new(libpcap_options_t opts, capture_stats_t *stats, char *errbuf);
void libpcap_capturer_destory(capturer_base_t *capturer);

#endif /* CPWORKER_LIBPCAP_H */