#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <pcap/pcap.h>

#include "bpf_util.h"
#include "capturer.h"
#include "errorf.h"
#include "if_util.h"
#include "libpcap.h"
#include "log.h"
#include "netns.h"
#include "pkt_dir.h"
#include "req_pattern.h"
#include "stats.h"

#define DROP_STAT_DUR_SEC 5

uint64_t libpcap_do_capture(capturer_base_t *self, capture_packet_handler pkt_handler,
                            capture_heartbeat_handler heartbeat_handler, void *user)
{
    libpcap_capturer_t *capturer = (libpcap_capturer_t *)self;

    struct pcap_pkthdr *hdr;
    const u_char *data;
    uint64_t retval;

    int direction;
    int ret = pcap_next_ex(capturer->p, &hdr, &data);
    switch (ret)
    {
    case 1:
        if (capturer->req_pattern == NULL)
            direction = PKT_DIR_NONCHECK;
        else
            direction = req_pattern_judge_pkt_direction(capturer->req_pattern, hdr, data);

        bytes_stats_add(&capturer->base.stats.cap_bytes, hdr->caplen);
        packets_stats_add(&capturer->base.stats.cap_packets, 1);
        pkt_handler(hdr, data, direction, user);
        retval = 1;
        break;
    case 0:
        // timeout
        heartbeat_handler(user);
        retval = 0;
        break;
    default:
        if (capturer->pcap_next_error[0] == '\0')
        {
            if (ret == PCAP_ERROR)
                snprintf(capturer->pcap_next_error, ERROR_BUFFER_SIZE, "pcap_next_ex error: %s",
                         pcap_geterr(capturer->p));
            else
                snprintf(capturer->pcap_next_error, ERROR_BUFFER_SIZE, "pcap_next_ex error_code: %d", ret);
        }
        retval = 0;
        break;
    }

    // drop stat
    if (!capturer->drop_stat_started)
    {
        time_t now = time(NULL);
        struct pcap_stat stat;
        if (pcap_stats(capturer->p, &stat) == 0)
        {
            capturer->drop_stat_started = true;
            capturer->drop_prev_packets = stat.ps_drop;
            capturer->ifdrop_prev_packets = stat.ps_ifdrop;
            capturer->drop_stat_prev_time = now;
        }

        return retval;
    }

    time_t now = time(NULL);
    if (difftime(now, capturer->drop_stat_prev_time) < DROP_STAT_DUR_SEC)
        return retval;

    struct pcap_stat stat;
    if (pcap_stats(capturer->p, &stat) == 0)
    {
        uint32_t drop_diff = stat.ps_drop - capturer->drop_prev_packets;
        packets_stats_add(&capturer->base.stats.drop_packets, drop_diff);

        uint32_t ifdrop_diff = stat.ps_ifdrop - capturer->ifdrop_prev_packets;
        packets_stats_add(&capturer->base.stats.ifdrop_packets, ifdrop_diff);

        capturer->drop_prev_packets = stat.ps_drop;
        capturer->ifdrop_prev_packets = stat.ps_ifdrop;
        capturer->drop_stat_prev_time = now;
    }

    if (capturer->pcap_next_error[0] != '\0')
    {
        log_error(capturer->pcap_next_error);
        capturer->pcap_next_error[0] = '\0';
    }
    return retval;
}

libpcap_capturer_t *libpcap_capturer_new(libpcap_options_t opts, char *errbuf)
{
    bool has_netns = false;
    if (opts.netns && strcmp(opts.netns, "") != 0)
        has_netns = true;

    int self_netns_fd;
    if (has_netns)
    {
        self_netns_fd = open_self_netns(errbuf);
        if (self_netns_fd == -1)
            return NULL;

        if (enter_netns_by_path(opts.netns, errbuf) != 0)
        {
            close_netns_fd(self_netns_fd);
            return NULL;
        }
    }

    req_pattern_t *req_pattern = req_pattern_new_from_cfg(opts.req_pattern, opts.interface, errbuf);
    if (!req_pattern)
    {
        error_wrap_format(errbuf, "create req_pattern_t error");
        goto error2;
    }
    const char *version = pcap_lib_version();
    log_info("libpcap version: %s", version);

    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *p = pcap_create(opts.interface, pcap_errbuf);
    if (!p)
    {
        error_format(errbuf, "call pcap_create(%s) error: %s", opts.interface, pcap_errbuf);
        goto error1;
    }

    pcap_set_snaplen(p, opts.snaplen);
    // see: https://github.com/the-tcpdump-group/libpcap/issues/572#issuecomment-576039197
    pcap_set_timeout(p, opts.timeout_ms);
    pcap_set_promisc(p, opts.promisc);
    pcap_set_buffer_size(p, opts.buffer_size);

    if (pcap_activate(p) < 0)
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
        char *bpf_filter = bpf_filter_replace_nic(opts.bpf_filter, get_if_ip_addr, errbuf);
        if (bpf_filter == NULL)
        {
            error_wrap_format(errbuf, "invalid bpf: %s", opts.bpf_filter);
            goto error;
        }

        struct bpf_program bpf_prog;
        if (pcap_compile(p, &bpf_prog, bpf_filter, 0, 0) != 0)
        {
            error_format(errbuf, "compile bpf filter '%s' error: %s", bpf_filter, pcap_geterr(p));
            free(bpf_filter);
            goto error;
        }
        free(bpf_filter);

        if (pcap_setfilter(p, &bpf_prog) != 0)
        {
            error_format(errbuf, "call pcap_setfilter error: %s", pcap_geterr(p));
            goto error;
        }
    }

    if (has_netns && enter_netns_by_fd(self_netns_fd, errbuf) != 0)
    {
        close_netns_fd(self_netns_fd);
        goto error3;
    }

    libpcap_capturer_t *capturer = (libpcap_capturer_t *)calloc(1, sizeof(libpcap_capturer_t));
    if (!capturer)
    {
        error_format(errbuf, "failed to allocate memory for libpcap_capturer_t");
        goto error3;
    }
    capturer->base.capture = libpcap_do_capture;
    capturer->base.destory = libpcap_capturer_destory;
    capturer->req_pattern = req_pattern;
    capturer->p = p;
    capturer->pcap_next_error[0] = '\0';

    return capturer;

error:
    pcap_close(p);
error1:
    req_pattern_destory(req_pattern);
error2:
    if (has_netns)
    {
        char ns_errbuf[PCAP_ERRBUF_SIZE];
        if (enter_netns_by_fd(self_netns_fd, ns_errbuf) != 0)
            log_error("restore netns fail: %s", ns_errbuf);

        close_netns_fd(self_netns_fd);
    }
    return NULL;
error3:
    pcap_close(p);
    req_pattern_destory(req_pattern);
    return NULL;
}

capturer_base_t *libpcap_capture_new_from_cfg(TaskConfig *task_cfg, char *errbuf)
{
    char *bpf_filter =
        bpf_filter_exclude_task_output_hosts(task_cfg->capturer.config.libpcap.bpf_filter, task_cfg, errbuf);

    if (bpf_filter == NULL)
        return NULL;

    int buffer_size;
    int buffer_size_mb = task_cfg->capturer.config.libpcap.buffer_size_mb;
    if (buffer_size_mb > INT_MAX / 1024 / 1024)
    {
        log_warn("buffer_size is too large, set to %d", INT_MAX);
        buffer_size = INT_MAX;
    }
    else
    {
        buffer_size = buffer_size_mb * 1024 * 1024;
    }

    libpcap_options_t opts = {
        .interface = task_cfg->interface,
        .snaplen = task_cfg->snaplen,
        .timeout_ms = task_cfg->capturer.config.libpcap.timeout_ms,
        .promisc = 0,
        .buffer_size = buffer_size,
        .bpf_filter = bpf_filter,
        .netns = task_cfg->netns,
        .req_pattern = task_cfg->req_pattern,
    };
    log_info("libpcap options: interface=%s, snaplen=%d, timeout_ms=%d, buffer_size=%d, bpf_filter='%s', netns='%s'",
             opts.interface, opts.snaplen, opts.timeout_ms, opts.buffer_size, opts.bpf_filter, opts.netns);

    capturer_base_t *capturer = (capturer_base_t *)libpcap_capturer_new(opts, errbuf);
    free(bpf_filter);
    return capturer;
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