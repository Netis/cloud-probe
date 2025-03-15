#ifndef CPAGENT_LIBPCAP_H
#define CPAGENT_LIBPCAP_H

#include <pcap/pcap.h>

#include "capturer.h"

typedef struct LibpcapOptions
{
    char *interface;
    int snaplen;
    int timeout_ms;
    int promisc;
    int buffer_size;
    char *bpf_filter;
    char *netns;
} libpcap_options_t;

typedef struct LibpcapCapturer
{
    capturer_base_t base;

    pcap_t *p;
} libpcap_capturer_t;

libpcap_capturer_t *new_libpcap_capturer(libpcap_options_t opts, char *errbuf);
void free_libpcap_capturer(capturer_base_t *capturer);

#endif /* CPAGENT_LIBPCAP_H */