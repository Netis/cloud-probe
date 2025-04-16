#ifndef CPAGENT_IF_UTIL_H
#define CPAGENT_IF_UTIL_H

#include <stdint.h>

#include "ip.h"

int get_mac_addr(const char *ifname, uint8_t *mac_addr, char *errbuf);

int get_if_addr(const char *ifname, ip_addr_t *addr, char *errbuf);
char *bpf_filter_replace_nic(const char *input, char *errbuf);

#endif /* CPAGENT_IF_UTIL_H */