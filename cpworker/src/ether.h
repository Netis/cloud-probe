#ifndef CPWORKER_ETHER_H
#define CPWORKER_ETHER_H

#include <stdint.h>

#define MAC_ADDR_STR_BUFSIZE 18

void format_mac_addr(const uint8_t *mac_addr, char *buf);

#endif /* CPWORKER_ETHER_H */