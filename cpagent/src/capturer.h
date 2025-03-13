#ifndef CPAGENT_CAPTURER_H
#define CPAGENT_CAPTURER_H

#include <stdint.h>
#include <sys/types.h>

#include <pcap/pcap.h>

typedef void (*PacketHandler)(const struct pcap_pkthdr *header, const uint8_t *pkt_data);

typedef struct PacketCapturerBase
{
    int (*capture)(struct PacketCapturerBase *capturer, PacketHandler handler);
    void (*destory)(struct PacketCapturerBase *capturer);
} PacketCapturerBase;

#endif /* CPAGENT_CAPTURER_H */