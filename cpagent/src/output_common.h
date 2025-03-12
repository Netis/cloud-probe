#ifndef CPAGENT_OUTPUT_COMMON_H
#define CPAGENT_OUTPUT_COMMON_H

#include <endian.h>
#include <pcap/pcap.h>
#include <stdint.h>
#include <sys/time.h>

#define PKT_DIR_UNKNOWN -1
#define PKT_DIR_INCOMING 1
#define PKT_DIR_OUTGOING 2
#define PKT_DIR_NONCHECK 0

#define ETHER_TYPE_MPLS 0x8847

static inline uint64_t tv2us(const struct timeval *tv)
{
    uint64_t us;

    us = tv->tv_usec;
    us += (tv->tv_sec * 1000000);

    return us;
}

typedef struct
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int reserved0 : 3;    // MPLS Label
    unsigned int rra : 4;          // MPLS Label
    unsigned int magic_number : 1; // MPLS Label

    unsigned int service_tag_h : 8; // MPLS Label

    unsigned int bottom : 1;        // MPLS Bottom of Label Stack
    unsigned int reserved1 : 3;     // MPLS Experimental Bits;
    unsigned int service_tag_l : 4; // MPLS Label

    unsigned int reserved2 : 8; // MPLS TTL
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned int magic_number : 1; // MPLS Label
    unsigned int rra : 4;          // MPLS Label
    unsigned int reserved0 : 3;    // MPLS Label

    unsigned int service_tag_h : 8; // MPLS Label

    unsigned int service_tag_l : 4; // MPLS Label
    unsigned int reserved1 : 3;     // MPLS Experimental Bits;
    unsigned int bottom : 1;        // MPLS Bottom of Label Stack

    unsigned int reserved2 : 8; // MPLS TTL
#endif
} mpls_header;

typedef struct OutputStats
{
    uint64_t total_fwd_count;
    uint64_t total_fwd_bytes;
} OutputStats;

typedef struct OutputBase
{
    int (*send_packet)(struct OutputBase *output, const struct pcap_pkthdr *header, const uint8_t *pkt_data,
                       int direct);
    void (*destory)(struct OutputBase *output);
} OutputBase;

#endif /* CPAGENT_OUTPUT_COMMON_H */