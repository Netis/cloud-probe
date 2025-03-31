#ifndef CPAGENT_OUTPUT_H
#define CPAGENT_OUTPUT_H

#include <stdint.h>
#include <sys/types.h>

#include <pcap/pcap.h>

#include "common.h"
#include "taskconf.h"

typedef struct OutputStats
{
    bytes_stats_t fwd_bytes;
    packets_stats_t fwd_packets;

    bytes_stats_t direction_drop_bytes;
    packets_stats_t direction_drop_packets;

    bytes_stats_t error_drop_bytes;
    packets_stats_t error_drop_packets;

    bytes_stats_t ratelimit_drop_bytes;
    packets_stats_t ratelimit_drop_packets;
} output_stats_t;

typedef struct OutputBase
{
    int (*send_packet)(struct OutputBase *output, const struct pcap_pkthdr *header, const uint8_t *pkt_data,
                       int direct);
    void (*destory)(struct OutputBase *output);
    output_stats_t stats;
} output_base_t;

typedef output_base_t *(*OutputFactory)(TaskConfig *task_cfg, OutputConfig *output_cfg, char *errbuf);

typedef struct OutputEntry
{
    const char *name;
    OutputFactory factory;
} output_entry_t;

static inline int output_send_packet(output_base_t *output, const struct pcap_pkthdr *header, const uint8_t *pkt_data,
                                     int direct)
{
    return output->send_packet(output, header, pkt_data, direct);
}

static void destory_output(output_base_t *output) { output->destory(output); }

#endif /* CPAGENT_OUTPUT_H */