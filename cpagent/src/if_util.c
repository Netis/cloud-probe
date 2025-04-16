#include <ctype.h>
#include <errno.h>
#include <ifaddrs.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "config.h"

#if defined(OS_MACOS) || defined(OS_BSD)
#include <net/if_dl.h>
#elif defined(OS_LINUX)
#include <linux/if_packet.h>
#endif

#include "error.h"
#include "if_util.h"
#include "log.h"

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
        error_format(errbuf, "Failed to find MAC address for interface %s", ifname);
        return -1;
    }

    return 0;
}

int get_if_addr(const char *ifname, ip_addr_t *addr, char *errbuf)
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

char *bpf_filter_replace_nic(const char *input, char *errbuf)
{
    size_t buf_size = strlen(input) * 2;
    char *output = malloc(buf_size);
    char *out_ptr = output;
    const char *in_ptr = input;

    while (*in_ptr)
    {
        if (strncmp(in_ptr, "nic.", 4) != 0)
        {
            *out_ptr++ = *in_ptr++;
            continue;
        }

        const char *end = in_ptr + 4;
        while (*end && !isspace(*end))
            end++;

        int ifname_len = end - (in_ptr + 4);
        char ifname[ifname_len + 1];
        strncpy(ifname, in_ptr + 4, ifname_len);
        ifname[ifname_len] = '\0';

        char errbuf[ERROR_BUFFER_SIZE];
        ip_addr_t addr;
        if (get_if_addr(ifname, &addr, errbuf) != 0)
        {
            error_format(errbuf, "no ip found for interface %s", ifname);
            free(output);
            return NULL;
        }
        char ip_str[INET6_ADDRSTRLEN];
        format_ip_addr(&addr, ip_str, sizeof(ip_str));
        log_info("bpf_filter interface %s addresss is %s", ifname, ip_str);

        size_t ip_len = strlen(ip_str);
        size_t offset = out_ptr - output;
        size_t remaining = buf_size - offset - 1;
        if (ip_len > remaining)
        {
            buf_size += ip_len * 2;
            output = realloc(output, buf_size);
            out_ptr = output + offset;
        }

        strncpy(out_ptr, ip_str, ip_len);
        out_ptr += ip_len;
        in_ptr = end;
    }
    *out_ptr = '\0';
    return output;
}
