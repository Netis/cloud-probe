#include <errno.h>
#include <ifaddrs.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "build_config.h"

#if defined(OS_MACOS) || defined(OS_BSD)
#include <net/if_dl.h>
#elif defined(OS_LINUX)
#include <linux/if_packet.h>
#endif

#include "errorf.h"
#include "if_util.h"
#include "log.h"

int get_if_mac_addr(const char *ifname, uint8_t *mac_addr, char *errbuf)
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

    struct ifaddrs *ifap, *ifa;
    int found = 0;

    if (getifaddrs(&ifap) == -1)
    {
        error_format(errbuf, "getifaddrs error: %s", strerror(errno));
        return -1;
    }

    for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (strcmp(ifa->ifa_name, ifname) != 0)
            continue;

        if (!ifa->ifa_addr)
            continue;

#if defined(OS_MACOS) || defined(OS_BSD)
        if (ifa->ifa_addr->sa_family == AF_LINK)
        {
            struct sockaddr_dl *sdl = (struct sockaddr_dl *)ifa->ifa_addr;
            if (sdl->sdl_alen == ETHER_ADDR_LEN)
            {
                memcpy(mac_addr, LLADDR(sdl), ETHER_ADDR_LEN);
                found = 1;
                break;
            }
        }
#elif defined(OS_LINUX)
        if (ifa->ifa_addr->sa_family == AF_PACKET)
        {
            struct sockaddr_ll *sll = (struct sockaddr_ll *)ifa->ifa_addr;
            if (sll->sll_halen == ETHER_ADDR_LEN)
            {
                memcpy(mac_addr, sll->sll_addr, ETHER_ADDR_LEN);
                found = 1;
                break;
            }
        }
#endif
    }

    freeifaddrs(ifap);

    if (!found)
    {
        error_format(errbuf, "Failed to find MAC address for interface '%s'", ifname);
        return -1;
    }

    return 0;
}

int get_if_ip_addr(const char *ifname, ip_addr_t *addr, char *errbuf)
{
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1)
    {
        error_format(errbuf, "getifaddrs error");
        return -1;
    }

    int found = 0;
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_addr == NULL || strcmp(ifa->ifa_name, ifname) != 0)
            continue;

        if (ifa->ifa_addr->sa_family == AF_INET)
        {
            struct sockaddr_in *sin = (struct sockaddr_in *)ifa->ifa_addr;
            addr->type = IP_TYPE_IPv4;
            addr->data.v4 = sin->sin_addr;
            found = 1;
            break;
        }
        else if (ifa->ifa_addr->sa_family == AF_INET6)
        {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
            addr->type = IP_TYPE_IPv6;
            addr->data.v6 = sin6->sin6_addr;
            found = 1;
            break;
        }
    }

    freeifaddrs(ifaddr);

    if (!found)
    {
        error_format(errbuf, "No IPv4 address found for %s", ifname);
        return -1;
    }
    return 0;
}
