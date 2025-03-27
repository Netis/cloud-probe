#define _GNU_SOURCE // 启用GNU扩展
#include <errno.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

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

int set_cpu_affinity(int cpu)
{
    cpu_set_t cpu_mask;
    CPU_ZERO(&cpu_mask);
    CPU_SET(cpu, &cpu_mask);
    if (sched_setaffinity(0, sizeof(cpu_set_t), &cpu_mask) != 0)
    {
        return -1;
    }
    return 0;
}

void bytes_stats_add(bytes_stats_t *stat, uint64_t bytes)
{
    uint64_t new_eib = bytes / EIB_IN_BYTES;
    uint64_t new_bytes = bytes % EIB_IN_BYTES;

    stat->bytes += new_bytes;
    if (stat->bytes >= EIB_IN_BYTES)
    {
        stat->bytes -= EIB_IN_BYTES;
        new_eib += 1;
    }

    stat->eib += new_eib;
}

void packets_stats_add(packets_stats_t *stat, uint64_t packets)
{
    uint64_t new_peta = packets / PETA_IN_PACKETS;
    uint64_t new_packets = packets % PETA_IN_PACKETS;

    stat->packets += new_packets;
    if (stat->packets >= PETA_IN_PACKETS)
    {
        stat->packets -= PETA_IN_PACKETS;
        new_peta += 1;
    }

    stat->peta += new_peta;
}