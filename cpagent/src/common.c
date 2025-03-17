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
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <pcap/pcap.h>
#include <pcap/vlan.h>

#include "common.h"
#include "error.h"

int get_mac_addr(const char *ifname, uint8_t *mac_addr, char *errbuf)
{
    if (!ifname)
    {
        error_format(errbuf, "ifname is empty");
        return -1;
    }
    if (!mac_addr)
    {
        error_format(errbuf, "mac_addr buffer is NULL");
        return -1;
    }

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
    {
        error_format(errbuf, "create socket error: %s", strerror(errno));
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == -1)
    {
        close(sockfd);
        error_format(errbuf, "ioctl error: %s", strerror(errno));
        return -1;
    }

    close(sockfd);

    unsigned char *hwaddr = (unsigned char *)ifr.ifr_hwaddr.sa_data;
    memcpy(mac_addr, hwaddr, ETH_ALEN);
    return 0;
}

void format_mac_addr(const uint8_t *mac_addr, char *buf)
{
    char *ptr = buf;
    for (int i = 0; i < ETH_ALEN; ++i)
    {
        if (i > 0)
        {
            *ptr++ = ':';
        }
        ptr += sprintf(ptr, "%02x", mac_addr[i]);
    }
    *ptr = '\0';
}

void free_req_pattern(req_pattern_t *req_pattern)
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

static bool match_pattern_by_ipport(req_pattern_t *req_pattern, const struct in_addr *ip, const uint16_t port)
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

int classify_packet_direction(req_pattern_t *req_pattern, const struct pcap_pkthdr *header, const uint8_t *pkt_data)
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

        struct iphdr *ip_hdr = (struct iphdr *)(pkt_data + eth_hdr_len);
        size_t ip_hdr_len = ip_hdr->ihl * 4;
        uint16_t sport = 0;
        uint16_t dport = 0;
        switch (ip_hdr->protocol)
        {
        case IPPROTO_TCP:
            struct tcphdr *tcp_hdr = (struct tcphdr *)(pkt_data + eth_hdr_len + ip_hdr_len);
            sport = ntohs(tcp_hdr->source);
            dport = ntohs(tcp_hdr->dest);
            break;
        case IPPROTO_UDP:
            struct udphdr *udp_hdr = (struct udphdr *)(pkt_data + eth_hdr_len + ip_hdr_len);
            sport = ntohs(udp_hdr->source);
            dport = ntohs(udp_hdr->dest);

            // TODO: check vxlan
            break;
        }

        if (match_pattern_by_ipport(req_pattern, (const struct in_addr *)&ip_hdr->saddr, sport))
            return PKT_DIR_OUTGOING;
        else if (match_pattern_by_ipport(req_pattern, (const struct in_addr *)&ip_hdr->daddr, dport))
            return PKT_DIR_INCOMING;
        else
            return PKT_DIR_UNKNOWN;

        break;
    case ETHERTYPE_VLAN:
        if (req_pattern->type == REQ_PATTERN_TYPE_NONE)
            return PKT_DIR_NONCHECK;

        struct vlanhdr *vlan_hdr = (struct vlanhdr *)(pkt_data + eth_hdr_len);
        uint16_t h_proto = ntohs(vlan_hdr->h_proto);
        switch (h_proto)
        {
        case ETHERTYPE_IP:
            struct iphdr *ip_hdr = (struct iphdr *)(pkt_data + eth_hdr_len + VLAN_TAG_LEN);
            size_t ip_hdr_len = ip_hdr->ihl * 4;
            uint16_t sport = 0;
            uint16_t dport = 0;
            switch (ip_hdr->protocol)
            {
            case IPPROTO_TCP:
                struct tcphdr *tcp_hdr = (struct tcphdr *)(pkt_data + eth_hdr_len + VLAN_TAG_LEN + ip_hdr_len);
                sport = ntohs(tcp_hdr->source);
                dport = ntohs(tcp_hdr->dest);
                break;
            case IPPROTO_UDP:
                struct udphdr *udp_hdr = (struct udphdr *)(pkt_data + eth_hdr_len + VLAN_TAG_LEN + ip_hdr_len);
                sport = ntohs(udp_hdr->source);
                dport = ntohs(udp_hdr->dest);
            }

            if (match_pattern_by_ipport(req_pattern, (const struct in_addr *)&ip_hdr->saddr, sport))
                return PKT_DIR_OUTGOING;
            else if (match_pattern_by_ipport(req_pattern, (const struct in_addr *)&ip_hdr->daddr, dport))
                return PKT_DIR_INCOMING;
            else
                return PKT_DIR_UNKNOWN;

            break;
        default:
            break;
        }
        break;
    default:
        break;
    }
    return PKT_DIR_UNKNOWN;
}
