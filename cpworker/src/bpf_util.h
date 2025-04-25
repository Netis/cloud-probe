#ifndef CPWORKER_BPF_UTIL_H
#define CPWORKER_BPF_UTIL_H

#include "if_util.h"

char *bpf_filter_replace_nic(const char *bpf, get_if_ip_addr_fn get_ip, char *errbuf);

#endif /* CPWORKER_BPF_UTIL_H */