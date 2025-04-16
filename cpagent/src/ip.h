#ifndef CPAGENT_IP_H
#define CPAGENT_IP_H

/*
#include <linux/ipv6.h>
#include <linux/ip.h>
*/
#include <netinet/in.h>
#include <stdint.h>

#include "byteorder.h"

struct ipv4_hdr
{
#if ENDIANNESS_LE
    unsigned int ihl : 4;
    unsigned int version : 4;
#elif ENDIANNESS_BE
    unsigned int version : 4;
    unsigned int ihl : 4;
#else
#error "Please fix byteorder.h"
#endif
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
    /*The options start here. */
};

struct ipv6_hdr
{
#if ENDIANNESS_LE
    uint8_t priority : 4, version : 4;
#elif ENDIANNESS_BE
    uint8_t version : 4, priority : 4;
#else
#error "Please fix byteorder.h"
#endif
    uint8_t flow_lbl[3];

    uint16_t payload_len;
    uint8_t nexthdr;
    uint8_t hop_limit;

    struct in6_addr saddr;
    struct in6_addr daddr;
};

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

int format_ip_addr(const ip_addr_t *addr, char *buf, size_t buflen);
bool ip_addr_equal(const ip_addr_t *a, const ip_addr_t *b);

#endif /* CPAGENT_IP_H */
