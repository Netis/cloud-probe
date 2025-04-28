#ifndef CPWORKER_REQ_PATTERN_H
#define CPWORKER_REQ_PATTERN_H

#include <net/ethernet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <sys/types.h>

#include <pcap/pcap.h>

#include "config.h"
#include "if_util.h"
#include "ip.h"

#define REQ_PATTERN_TYPE_NONE 0
#define REQ_PATTERN_TYPE_AUTO 1
#define REQ_PATTERN_TYPE_CUSTOM 2

typedef struct ReqPatternCustomMatcher
{
    void *node;
} req_pattern_custom_matcher_t;

typedef struct ReqPatternAutoMatcher
{
    uint8_t mac_addr[ETHER_ADDR_LEN];
} req_pattern_auto_matcher_t;

typedef struct ReqPattern
{
    int type;
    union
    {
        req_pattern_auto_matcher_t _auto;
        req_pattern_custom_matcher_t custom;
    } matcher;
} req_pattern_t;

int req_pattern_custom_matcher_init(req_pattern_custom_matcher_t *matcher, const char *pattern,
                                    get_if_ip_addr_fn get_ip);
void req_pattern_custom_matcher_destroy(req_pattern_custom_matcher_t *matcher);
bool req_pattern_custom_match_by_ipport(req_pattern_custom_matcher_t *matcher, const ip_addr_t *ip, uint16_t port);

req_pattern_t *req_pattern_new_from_cfg(ReqPatternConfig cfg, const char *ifname, char *errbuf);
void req_pattern_destory(req_pattern_t *req_pattern);
int req_pattern_judge_pkt_direction(req_pattern_t *req_pattern, const struct pcap_pkthdr *header,
                                    const uint8_t *pkt_data);

#endif /* CPWORKER_REQ_PATTERN_H */