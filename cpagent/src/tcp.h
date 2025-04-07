#ifndef CPAGENT_TCP_H
#define CPAGENT_TCP_H

#include <stdint.h>

struct tcphdr
{
    uint16_t sport;   /* source port */
    uint16_t dport;   /* destination port */
    uint32_t seq;     /* sequence number */
    uint32_t ack_seq; /* acknowledgement number */
    uint8_t offx2;    /* data offset, rsvd */
    uint8_t flags;
    uint16_t window;  /* window */
    uint16_t check;   /* checksum */
    uint16_t urg_ptr; /* urgent pointer */
};

#endif /* CPAGENT_TCP_H */
