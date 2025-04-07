#ifndef CPAGENT_COMMON_H
#define CPAGENT_COMMON_H

#include <netinet/in.h>
#include <stdint.h>

#include "byteorder.h"

#define PKT_DIR_UNKNOWN -1
#define PKT_DIR_NONCHECK 0
#define PKT_DIR_INCOMING 1
#define PKT_DIR_OUTGOING 2

#define ETHER_TYPE_MPLS 0x8847

#define MAC_ADDR_STR_BUFSIZE 18
#define VXLAN_HEADER_LEN 8
#define GRE_HEADER_LEN 8

#define EIB_IN_BYTES (1024ULL * 1024 * 1024 * 1024 * 1024 * 1024) // 1 EiB = 2^60 bytes
#define PETA_IN_PACKETS 10000000000000000ULL                      // 1 Peta = 10^16 packets

typedef struct
{
#if ENDIANNESS_LE
    unsigned int reserved0 : 3;    // MPLS Label
    unsigned int rra : 4;          // MPLS Label
    unsigned int magic_number : 1; // MPLS Label

    unsigned int service_tag_h : 8; // MPLS Label

    unsigned int bottom : 1;        // MPLS Bottom of Label Stack
    unsigned int reserved1 : 3;     // MPLS Experimental Bits;
    unsigned int service_tag_l : 4; // MPLS Label

    unsigned int reserved2 : 8; // MPLS TTL
#elif ENDIANNESS_BE
    unsigned int magic_number : 1; // MPLS Label
    unsigned int rra : 4;          // MPLS Label
    unsigned int reserved0 : 3;    // MPLS Label

    unsigned int service_tag_h : 8; // MPLS Label

    unsigned int service_tag_l : 4; // MPLS Label
    unsigned int reserved1 : 3;     // MPLS Experimental Bits;
    unsigned int bottom : 1;        // MPLS Bottom of Label Stack

    unsigned int reserved2 : 8; // MPLS TTL
#else
#error "Please fix byteorder.h"
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

typedef struct
{
    uint64_t bytes;
    uint64_t eib;
} bytes_stats_t;

typedef struct
{
    uint64_t packets;
    uint64_t peta;
} packets_stats_t;

typedef enum
{
    IP_TYPE_IPv4,
    IP_TYPE_IPv6
} IPType;

typedef struct
{
    IPType type;
    union
    {
        struct in_addr v4;
        struct in6_addr v6;
    } data;
} ip_addr_t;

int get_mac_addr(const char *ifname, uint8_t *mac_addr, char *errbuf);
void format_mac_addr(const uint8_t *mac_addr, char *buf);

int get_if_addr(const char *ifname, ip_addr_t *addr, char *errbuf);
int format_ip_addr(ip_addr_t *addr, char *buf, size_t buflen);
char *bpf_filter_replace_nic(const char *input, char *errbuf);

void bytes_stats_add(bytes_stats_t *stat, uint64_t bytes);
void packets_stats_add(packets_stats_t *stat, uint64_t packets);

#endif /* CPAGENT_COMMON_H */