#include <net/ethernet.h>
#include <stdio.h>

#include "ether.h"

void format_mac_addr(const uint8_t *mac_addr, char *buf)
{
    char *ptr = buf;
    for (int i = 0; i < ETHER_ADDR_LEN; ++i)
    {
        if (i > 0)
        {
            *ptr++ = ':';
        }
        ptr += sprintf(ptr, "%02x", mac_addr[i]);
    }
    *ptr = '\0';
}