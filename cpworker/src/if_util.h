#ifndef CPWORKER_IF_UTIL_H
#define CPWORKER_IF_UTIL_H

#include <stdint.h>

#include "ip.h"

typedef int (*get_if_mac_addr_fn)(const char *, uint8_t *, char *);
typedef int (*get_if_ip_addr_fn)(const char *, ip_addr_t *, char *);

int get_if_mac_addr(const char *ifname, uint8_t *mac_addr, char *errbuf);
int get_if_ip_addr(const char *ifname, ip_addr_t *addr, char *errbuf);

#endif /* CPWORKER_IF_UTIL_H */