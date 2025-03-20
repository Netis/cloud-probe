#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <pcap/pcap.h>

#include "capturer.h"
#include "common.h"
#include "error.h"
#include "libpcap.h"
#include "log.h"
#include "req_pattern.h"

int libpcap_do_capture(capturer_base_t *self, PacketHandler handler, void *user)
{
    libpcap_capturer_t *capturer = (libpcap_capturer_t *)self;

    struct pcap_pkthdr *hdr;
    const u_char *data;
    int ret = pcap_next_ex(capturer->p, &hdr, &data);
    switch (ret)
    {
    case 1:
        int direction = PKT_DIR_UNKNOWN;
        if (capturer->req_pattern == NULL)
            direction = PKT_DIR_NONCHECK;
        else
            direction = req_pattern_judge_pkt_direction(capturer->req_pattern, hdr, data);

        handler(hdr, data, direction, user);
        return 1;
    case 0:
        // timeout
        return 0;
    default:
        // error
        return 0;
    }
}

libpcap_capturer_t *libpcap_capturer_new(libpcap_options_t opts, char *errbuf)
{
    int self_netns_fd;
    if (opts.netns && strcmp(opts.netns, "") != 0)
    {
        self_netns_fd = get_self_netns_fd(errbuf);
        if (self_netns_fd == -1)
            return NULL;

        if (enter_netns_by_path(opts.netns, errbuf) != 0)
        {
            close(self_netns_fd);
            return NULL;
        }
    }

    req_pattern_t *req_pattern = req_pattern_new_from_cfg(opts.req_pattern, opts.interface, errbuf);
    if (!req_pattern)
    {
        error_wrap_format(errbuf, "create req_pattern_t error");
        return NULL;
    }

    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *p = pcap_create(opts.interface, pcap_errbuf);
    if (!p)
    {
        error_format(errbuf, "call pcap_create(%s) error: %s", opts.interface, pcap_errbuf);
        if (opts.netns && strcmp(opts.netns, "") != 0)
        {
            char ns_errbuf[PCAP_ERRBUF_SIZE];
            if (enter_netns_by_fd(self_netns_fd, ns_errbuf) != 0)
                log_error("restore netns fail: %s", ns_errbuf);
        }
        return NULL;
    }

    pcap_set_snaplen(p, opts.snaplen);
    pcap_set_timeout(p, opts.timeout_ms);
    pcap_set_promisc(p, opts.promisc);
    pcap_set_buffer_size(p, opts.buffer_size);

    if (pcap_activate(p) != 0)
    {
        error_format(errbuf, "call pcap_activate error: %s", pcap_geterr(p));
        goto error;
    }

    if (opts.timeout_ms == 0)
    {
        if (pcap_setnonblock(p, 1, pcap_errbuf) != 0)
        {
            error_format(errbuf, "pcap_setnonblock error: %s", pcap_errbuf);
            goto error;
        }
    }

    if (opts.bpf_filter && strcmp(opts.bpf_filter, "") != 0)
    {
        struct bpf_program bpf_prog;
        if (pcap_compile(p, &bpf_prog, opts.bpf_filter, 0, 0) != 0)
        {
            error_format(errbuf, "compile bpf filter '%s' error: %s", opts.bpf_filter, pcap_geterr(p));
            goto error;
        }
        if (pcap_setfilter(p, &bpf_prog) != 0)
        {
            error_format(errbuf, "call pcap_setfilter error: %s", pcap_geterr(p));
            goto error;
        }
    }

    if (opts.netns && strcmp(opts.netns, "") != 0)
    {
        if (enter_netns_by_fd(self_netns_fd, errbuf) != 0)
        {
            pcap_close(p);
            return NULL;
        }
    }

    libpcap_capturer_t *capturer = (libpcap_capturer_t *)calloc(1, sizeof(libpcap_capturer_t));
    if (!capturer)
    {
        error_format(errbuf, "failed to allocate memory for libpcap_capturer_t");
        pcap_close(p);
        return NULL;
    }
    capturer->base.capture = libpcap_do_capture;
    capturer->base.destory = libpcap_capturer_destory;
    capturer->p = p;
    return capturer;

error:
    pcap_close(p);
    if (opts.netns && strcmp(opts.netns, "") != 0)
    {
        char ns_errbuf[PCAP_ERRBUF_SIZE];
        if (enter_netns_by_fd(self_netns_fd, ns_errbuf) != 0)
            log_error("restore netns fail: %s", ns_errbuf);
    }
    return NULL;
}

capturer_base_t *libpcap_capture_new_from_cfg(TaskConfig *task_cfg, char *errbuf)
{
    libpcap_options_t opts = {
        .interface = task_cfg->interface,
        .snaplen = task_cfg->snaplen,
        .promisc = 0,
        .buffer_size = task_cfg->capturer.config.libpcap.buffer_size_mb * 1024 * 1024,
        .bpf_filter = task_cfg->capturer.config.libpcap.bpf_filter,
        .netns = task_cfg->netns,
        .req_pattern = task_cfg->req_pattern,
    };
    log_info("libpcap options, interface %s, snaplen %d, buffer_size: %d, bpf_filter: `%s`", opts.interface,
             opts.snaplen, opts.buffer_size, opts.bpf_filter);

    return (capturer_base_t *)libpcap_capturer_new(opts, errbuf);
}

void libpcap_capturer_destory(capturer_base_t *self)
{
    if (!self)
        return;

    libpcap_capturer_t *capturer = (libpcap_capturer_t *)self;

    log_info("free libpcap capturer");
    req_pattern_destory(capturer->req_pattern);
    pcap_close(capturer->p);
    free(capturer);
}