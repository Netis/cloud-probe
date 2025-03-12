#ifndef CPAGENT_CAPTURER_H
#define CPAGENT_CAPTURER_H

#include <pcap/pcap.h>
#include <stdint.h>

typedef void (*PacketHandler)(const struct pcap_pkthdr *header, const uint8_t *pkt_data);

typedef struct PacketCapturerBase
{
    int (*capture)(PacketCapturerBase *dumper, PacketHandler handler);
    void (*destory)(struct PacketCapturerBase *dumper);
} PacketCapturerBase;

#endif /* CPAGENT_CAPTURER_H */