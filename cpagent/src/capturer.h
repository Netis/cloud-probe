#ifndef CPAGENT_CAPTURER_H
#define CPAGENT_CAPTURER_H

#include <stdint.h>
#include <sys/types.h>

#include <pcap/pcap.h>

#include "common.h"
#include "taskconf.h"

typedef struct CaptureStats
{
    bytes_stats_t cap_bytes;
    packets_stats_t cap_packets;

    packets_stats_t drop_packets;
    packets_stats_t ifdrop_packets;
} capture_stats_t;

typedef void (*PacketHandler)(const struct pcap_pkthdr *header, const uint8_t *pkt_data, int direct, void *user);

typedef struct CapturerBase
{
    uint64_t (*capture)(struct CapturerBase *capturer, PacketHandler handler, void *user);
    void (*destory)(struct CapturerBase *capturer);
    capture_stats_t stats;
} capturer_base_t;

typedef capturer_base_t *(*CapturerFactory)(TaskConfig *task_cfg, char *errbuf);

typedef struct CapturerEntry
{
    const char *name;
    CapturerFactory factory;
} capturer_entry_t;

static uint64_t capture_packets(capturer_base_t *capturer, PacketHandler handler, void *user)
{
    return capturer->capture(capturer, handler, user);
}

static void destory_capturer(capturer_base_t *capturer) { capturer->destory(capturer); }

#endif /* CPAGENT_CAPTURER_H */