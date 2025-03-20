#ifndef CPAGENT_REQ_PATTERN_H
#define CPAGENT_REQ_PATTERN_H

#include <linux/if_ether.h>
#include <netinet/in.h>
#include <stdint.h>
#include <sys/types.h>

#include <pcap/pcap.h>

#include "taskconf.h"

#define REQ_PATTERN_TYPE_NONE 0
#define REQ_PATTERN_TYPE_AUTO 1
#define REQ_PATTERN_TYPE_CUSTOM 2

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

req_pattern_t *req_pattern_new_from_cfg(ReqPatternConfig cfg, const char *interface, char *errbuf);
void req_pattern_destory(req_pattern_t *req_pattern);
int req_pattern_judge_pkt_direction(req_pattern_t *req_pattern, const struct pcap_pkthdr *header,
                                    const uint8_t *pkt_data);

#endif /* CPAGENT_REQ_PATTERN_H */