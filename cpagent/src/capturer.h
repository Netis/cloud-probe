#ifndef CPAGENT_CAPTURER_H
#define CPAGENT_CAPTURER_H

#include <stdint.h>
#include <sys/types.h>

#include <pcap/pcap.h>

typedef void (*PacketHandler)(const struct pcap_pkthdr *header, const uint8_t *pkt_data, void *user);

typedef struct CapturerBase
{
    int (*capture)(struct CapturerBase *capturer, PacketHandler handler, void *user);
    void (*destory)(struct CapturerBase *capturer);
} capturer_base_t;

#endif /* CPAGENT_CAPTURER_H */