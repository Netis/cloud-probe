#ifndef CPAGENT_COMMON_H
#define CPAGENT_COMMON_H

#include <endian.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/time.h>
#include <sys/types.h>

#include <pcap/pcap.h>

#define PKT_DIR_UNKNOWN -1
#define PKT_DIR_INCOMING 1
#define PKT_DIR_OUTGOING 2
#define PKT_DIR_NONCHECK 0

#define REQ_PATTERN_TYPE_NONE 0
#define REQ_PATTERN_TYPE_AUTO 1
#define REQ_PATTERN_TYPE_CUSTOM 2

#define ETHER_TYPE_MPLS 0x8847

#define MAC_ADDR_STR_BUFSIZE 18
#define VXLAN_HEADER_LEN 8

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

typedef struct
{
    uint8_t reserved1 : 4;
    uint8_t rra : 4;
    uint8_t service_tag_h : 4;
    uint8_t reserved2 : 4;
    uint8_t service_tag_l : 8;
    uint8_t check;
} pa_tag_t;

struct vxlanhdr
{
    uint32_t vx_flags;
    uint32_t vx_vni;
};

struct vlanhdr
{
    uint16_t tci;
    uint16_t h_proto;
};

typedef struct ReqPattern
{
    int type;
    union
    {
        struct
        {
            uint8_t mac_addr[ETH_ALEN];
        } _auto;
        struct
        {
            struct in_addr *ips;
            int num_ips;

            uint32_t *ports;
            int num_ports;
        } custom;

    } config;
} req_pattern_t;

static inline uint64_t tv2us(const struct timeval *tv)
{
    uint64_t us;

    us = tv->tv_usec;
    us += (tv->tv_sec * 1000000);

    return us;
}

int get_mac_addr(const char *ifname, uint8_t *mac_addr, char *errbuf);
void format_mac_addr(const uint8_t *mac_addr, char *buf);
void free_req_pattern(req_pattern_t *req_pattern);
int classify_packet_direction(req_pattern_t *req_pattern, const struct pcap_pkthdr *header, const uint8_t *pkt_data);

#endif /* CPAGENT_COMMON_H */