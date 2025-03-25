#include <errno.h>
#include <linux/if_ether.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <pcap/pcap.h>
#include <pcap/vlan.h>

#include "common.h"
#include "error.h"
#include "log.h"
#include "req_pattern.h"

void req_pattern_destory(req_pattern_t *req_pattern)
{
    if (!req_pattern)
        return;

    switch (req_pattern->type)
    {
    case REQ_PATTERN_TYPE_CUSTOM:
        if (req_pattern->config.custom.num_ips > 0)
        {
            free(req_pattern->config.custom.ips);
            req_pattern->config.custom.ips = NULL;
            req_pattern->config.custom.num_ips = 0;
        }
        if (req_pattern->config.custom.num_ports > 0)
        {
            free(req_pattern->config.custom.ports);
            req_pattern->config.custom.ports = NULL;
            req_pattern->config.custom.num_ports = 0;
        }
        break;
    }
    free(req_pattern);
}

req_pattern_t *req_pattern_new_from_cfg(ReqPatternConfig cfg, const char *interface, char *errbuf)
{
    req_pattern_t *req_pattern = (req_pattern_t *)calloc(1, sizeof(req_pattern_t *));
    if (!req_pattern)
    {
        error_format(errbuf, "failed to allocate memory for req_pattern_t");
        return NULL;
    }

    if (strcmp(cfg.type, REQ_PATTERN_TYPE_NONE_STR) == 0)
        req_pattern->type = REQ_PATTERN_TYPE_NONE;
    else if (strcmp(cfg.type, REQ_PATTERN_TYPE_AUTO_STR) == 0)
    {
        if (get_mac_addr(interface, req_pattern->config._auto.mac_addr, errbuf) != 0)
            goto error;

        req_pattern->type = REQ_PATTERN_TYPE_AUTO;

        char mac_addr_str[MAC_ADDR_STR_BUFSIZE];
        format_mac_addr(req_pattern->config._auto.mac_addr, mac_addr_str);
        log_info("interface '%s' mac addr: %s", interface, mac_addr_str);
    }
    else if (strcmp(cfg.type, REQ_PATTERN_TYPE_CUSTOM_STR) == 0)
    {
        // pattern example:
        // 1. host nic.eth0 and port 8011
        // 2. (host 172.16.1.1 or host 172.16.1.2) and port 8011
        // 3. host 172.16.1.1 and (port 8011 or port 8012)
        // 4. (host 172.16.1.1 or host 172.16.1.2) and (port 8011 or port 8012)
        req_pattern->type = REQ_PATTERN_TYPE_CUSTOM;
        // TODO: parse custom
    }
    return req_pattern;

error:
    req_pattern_destory(req_pattern);
    return NULL;
}

static bool req_pattern_match_by_ipport(req_pattern_t *req_pattern, const struct in_addr *ip, const uint16_t port)
{
    if (req_pattern->type != REQ_PATTERN_TYPE_CUSTOM)
        return false;

    bool match = false;
    for (int i = 0; i < req_pattern->config.custom.num_ips; ++i)
    {
        if (req_pattern->config.custom.ips[i].s_addr == ip->s_addr)
        {
            match = true;
            break;
        }
    }

    if (match)
    {
        for (int i = 0; i < req_pattern->config.custom.num_ports; ++i)
        {
            if (req_pattern->config.custom.ports[i] == port)
                return true;

            match = false;
        }
    }
    return match;
}

static int req_pattern_judge_pkt_dir_by_ipv4(req_pattern_t *req_pattern, const struct pcap_pkthdr *header,
                                             const uint8_t *pkt_data, size_t ip_hdr_offset)
{

    struct iphdr *ip_hdr = (struct iphdr *)(pkt_data + ip_hdr_offset);
    size_t ip_hdr_len = ip_hdr->ihl * 4;
    uint16_t sport = 0;
    uint16_t dport = 0;

    switch (ip_hdr->protocol)
    {
    case IPPROTO_TCP:
        struct tcphdr *tcp_hdr = (struct tcphdr *)(pkt_data + ip_hdr_offset + ip_hdr_len);
        sport = ntohs(tcp_hdr->source);
        dport = ntohs(tcp_hdr->dest);
        break;
    case IPPROTO_UDP:
        struct udphdr *udp_hdr = (struct udphdr *)(pkt_data + ip_hdr_offset + ip_hdr_len);
        sport = ntohs(udp_hdr->source);
        dport = ntohs(udp_hdr->dest);

        // TODO: check vxlan
        break;
    }

    if (req_pattern_match_by_ipport(req_pattern, (const struct in_addr *)&ip_hdr->saddr, sport))
        return PKT_DIR_OUTGOING;
    else if (req_pattern_match_by_ipport(req_pattern, (const struct in_addr *)&ip_hdr->daddr, dport))
        return PKT_DIR_INCOMING;
    else
        return PKT_DIR_UNKNOWN;
}

int req_pattern_judge_pkt_direction(req_pattern_t *req_pattern, const struct pcap_pkthdr *header,
                                    const uint8_t *pkt_data)
{
    struct ether_header *eth_hdr;
    eth_hdr = (struct ether_header *)pkt_data;

    if (req_pattern->type == REQ_PATTERN_TYPE_AUTO)
    {
        if (memcmp(eth_hdr->ether_shost, req_pattern->config._auto.mac_addr, ETH_ALEN) == 0)
            return PKT_DIR_OUTGOING;
        else
            return PKT_DIR_INCOMING;
    }

    size_t eth_hdr_len = sizeof(struct ether_header);
    uint16_t eth_type = ntohs(eth_hdr->ether_type);
    switch (eth_type)
    {
    case ETHERTYPE_IP:
        if (req_pattern->type == REQ_PATTERN_TYPE_NONE)
            return PKT_DIR_NONCHECK;

        return req_pattern_judge_pkt_dir_by_ipv4(req_pattern, header, pkt_data, eth_hdr_len);
    case ETHERTYPE_VLAN:
        if (req_pattern->type == REQ_PATTERN_TYPE_NONE)
            return PKT_DIR_NONCHECK;

        struct vlanhdr *vlan_hdr = (struct vlanhdr *)(pkt_data + eth_hdr_len);
        uint16_t h_proto = ntohs(vlan_hdr->h_proto);
        switch (h_proto)
        {
        case ETHERTYPE_IP:
            return req_pattern_judge_pkt_dir_by_ipv4(req_pattern, header, pkt_data, eth_hdr_len + VLAN_TAG_LEN);
        default:
            break;
        }
        break;
    default:
        // other protocols
        break;
    }
    return PKT_DIR_UNKNOWN;
}
