#ifndef CPAGENT_OUTPUT_H
#define CPAGENT_OUTPUT_H

#include <stdint.h>
#include <sys/types.h>

#include <pcap/pcap.h>

typedef struct OutputStats
{
    uint64_t total_fwd_count;
    uint64_t total_fwd_bytes;
} output_stats_t;

typedef struct OutputBase
{
    int (*send_packet)(struct OutputBase *output, const struct pcap_pkthdr *header, const uint8_t *pkt_data,
                       int direct);
    void (*destory)(struct OutputBase *output);
} output_base_t;

static inline int output_send_packet(output_base_t *output, const struct pcap_pkthdr *header, const uint8_t *pkt_data,
                                     int direct)
{
    return output->send_packet(output, header, pkt_data, direct);
}

static void destory_output(output_base_t *output) { output->destory(output); }

#endif /* CPAGENT_OUTPUT_H */