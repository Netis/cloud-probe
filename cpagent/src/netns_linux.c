#include "netns.h"

#if defined(NETNS_LINUX)

#ifdef __linux__
#define _GNU_SOURCE // 启用GNU扩展
#include <sched.h>
#endif

#include <fcntl.h>
#include <unistd.h>

#include "error.h"

int open_self_netns(char *errbuf)
{
    const char *ns_path = "/proc/self/ns/net";
    int fd = open(ns_path, O_RDONLY);
    if (fd == -1)
    {
        error_format(errbuf, "open %s error", ns_path);
        return -1;
    }
    return fd;
}

int enter_netns_by_path(char *ns_path, char *errbuf)
{
    int fd = open(ns_path, O_RDONLY);
    if (fd == -1)
    {
        error_format(errbuf, "open '%s' error", ns_path);
        return -1;
    }
    if (setns(fd, CLONE_NEWNET) == -1)
    {
        error_format(errbuf, "call setns for '%s' error", ns_path);
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

int enter_netns_by_fd(int fd, char *errbuf)
{
    if (setns(fd, CLONE_NEWNET) == -1)
    {
        error_format(errbuf, "call setns error");
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

int close_netns_fd(int fd) { return close(fd); }

#endif