#define _GNU_SOURCE
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <unistd.h>

#include "capturer.h"
#include "error.h"

int get_self_netns_fd(char *errbuf)
{
    const char *ns_path = "/proc/self/ns/net";
    int fd = open(ns_path, O_RDONLY);
    if (fd == -1)
    {
        snprintf(errbuf, ERROR_BUFFER_SIZE, "open %s error", ns_path);
        return -1;
    }
    return fd;
}

int enter_netns_by_path(char *ns_path, char *errbuf)
{
    int fd = open(ns_path, O_RDONLY);
    if (fd == -1)
    {
        snprintf(errbuf, ERROR_BUFFER_SIZE, "open '%s' error", ns_path);
        return -1;
    }
    if (setns(fd, CLONE_NEWNET) == -1)
    {
        snprintf(errbuf, ERROR_BUFFER_SIZE, "call setns for '%s' error", ns_path);
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
        snprintf(errbuf, ERROR_BUFFER_SIZE, "call setns error");
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}