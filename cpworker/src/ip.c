#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "ip.h"

bool ip_addr_equal(const ip_addr_t *a, const ip_addr_t *b)
{
    if (a->type != b->type)
        return false;

    switch (a->type)
    {
    case IP_TYPE_IPv4:
        return a->data.v4.s_addr == b->data.v4.s_addr;
    case IP_TYPE_IPv6:
        return memcmp(a->data.v6.s6_addr, b->data.v6.s6_addr, 16) == 0;
    default:
        return false;
    }
}

int format_ip_addr(const ip_addr_t *addr, char *buf, size_t buflen)
{
    if (!addr || !buf || buflen < 1)
        return -1;

    size_t required_len = (addr->type == IP_TYPE_IPv4) ? INET_ADDRSTRLEN : INET6_ADDRSTRLEN;
    if (buflen < required_len)
    {
        buf[0] = '\0';
        return -2;
    }

    const char *result = NULL;
    switch (addr->type)
    {
    case IP_TYPE_IPv4:
        result = inet_ntop(AF_INET, &addr->data.v4, buf, INET_ADDRSTRLEN);
        break;
    case IP_TYPE_IPv6:
        result = inet_ntop(AF_INET6, &addr->data.v6, buf, INET6_ADDRSTRLEN);
        break;
    default:
        buf[0] = '\0';
        return -3;
    }

    if (result == NULL)
    {
        buf[0] = '\0';
        return -3;
    }
    return 0;
}