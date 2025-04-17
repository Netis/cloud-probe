#ifndef CPAGENT_BPF_UTIL_H
#define CPAGENT_BPF_UTIL_H

#include "if_util.h"

char *bpf_filter_replace_nic(const char *bpf, get_if_ip_addr_fn get_ip, char *errbuf);

#endif /* CPAGENT_BPF_UTIL_H */