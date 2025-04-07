#ifndef CPAGENT_IP_H
#define CPAGENT_IP_H

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

#endif /* CPAGENT_IP_H */
