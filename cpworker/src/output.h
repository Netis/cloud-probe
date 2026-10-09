#ifndef CPWORKER_OUTPUT_H
#define CPWORKER_OUTPUT_H

#include <stdint.h>
#include <sys/types.h>

#include <pcap/pcap.h>

#include "config.h"
#include "stats.h"

typedef struct OutputBase
{
    int (*send_packet)(struct OutputBase *output, const struct pcap_pkthdr *header, const uint8_t *pkt_data,
                       int direct);
    void (*heartbeat)(struct OutputBase *output, time_t now);
    void (*destroy)(struct OutputBase *output);
    output_stats_t *stats;
} output_base_t;

typedef output_base_t *(*OutputFactory)(TaskConfig *task_cfg, OutputConfig *output_cfg, output_stats_t *stats,
                                        char *errbuf);

typedef struct OutputEntry
{
    const char *name;
    OutputFactory factory;
} output_entry_t;

// Length of the frame an output carries and counts: the captured length after slice, capped at
// the largest frame the output can carry. Every output counter and rate limiter uses this length.
static inline size_t output_frame_len(uint32_t caplen, int slice, size_t max_len)
{
    size_t frame_len = caplen;
    if (slice > 0 && (uint32_t)slice < caplen)
        frame_len = (size_t)slice;
    return frame_len < max_len ? frame_len : max_len;
}

static inline int output_send_packet(output_base_t *output, const struct pcap_pkthdr *header, const uint8_t *pkt_data,
                                     int direct)
{
    return output->send_packet(output, header, pkt_data, direct);
}

static inline void output_heartbeat(output_base_t *output, time_t now)
{
    if (output->heartbeat)
        output->heartbeat(output, now);
}

static inline void destroy_output(output_base_t *output) { output->destroy(output); }

#endif /* CPWORKER_OUTPUT_H */