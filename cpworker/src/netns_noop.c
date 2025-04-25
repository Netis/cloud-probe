#include "netns.h"

#if defined(NETNS_NOOP)

int open_self_netns(char *errbuf) { return 0; }
int enter_netns_by_path(char *ns_path, char *errbuf) { return 0; }
int enter_netns_by_fd(int fd, char *errbuf) { return 0; }
int close_netns_fd(int fd) { return 0; }

#endif