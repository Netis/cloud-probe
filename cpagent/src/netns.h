#ifndef CPAGENT_NETNS_H
#define CPAGENT_NETNS_H

#include "config.h"

#if defined(OS_LINUX)
#define NETNS_LINUX 1
#else
#define NETNS_NOOP 1
#endif

int open_self_netns(char *errbuf);
int enter_netns_by_path(char *ns_path, char *errbuf);
int enter_netns_by_fd(int fd, char *errbuf);
int close_netns_fd(int fd);

#endif /* CPAGENT_NETNS_H */