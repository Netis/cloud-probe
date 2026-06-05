#include <limits.h>
#include <stdlib.h>
#include <string.h>
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

// pcap_set_immediate_mode() only exists in libpcap >= 1.5.0. cpworker may run against an
// older system libpcap than the one it was built with (it resolves libpcap.so.1 from the
// OS at runtime, not the bundled copy), so reference the symbol weakly and call it only
// when present. On libpcap < 1.5.0 the symbol is absent (resolves to NULL) and the loader
// will not fail; those versions use TPACKET_V2 (per-frame delivery) which has no block
// retire latency to fix anyway.
extern int pcap_set_immediate_mode(pcap_t *p, int immediate) __attribute__((weak));

#define DROP_STAT_DUR_SEC 2

uint64_t libpcap_do_capture(capturer_base_t *self, capture_packet_handler pkt_handler,
                            capture_heartbeat_handler heartbeat_handler, void *user)
{
    libpcap_capturer_t *capturer = (libpcap_capturer_t *)self;

    struct pcap_pkthdr *hdr;
    const u_char *data;
    uint64_t num_pkts = 0;

    int direction;
    int ret = pcap_next_ex(capturer->p, &hdr, &data);
    switch (ret)
    {
    case 1:
        if (capturer->req_pattern == NULL)
            direction = PKT_DIR_NONCHECK;
        else
            direction = req_pattern_judge_pkt_direction(capturer->req_pattern, hdr, data);

        bytes_stats_add(&capturer->base.stats->cap_bytes, hdr->caplen);
        packets_stats_add(&capturer->base.stats->cap_packets, 1);
        pkt_handler(hdr, data, direction, user);
        num_pkts = 1;
        break;
    case 0:
        // timeout
        heartbeat_handler(user);
        break;
    default:
        if (capturer->pcap_next_error[0] == '\0')
        {
            if (ret == PCAP_ERROR)
                snprintf(capturer->pcap_next_error, ERROR_BUFFER_SIZE, "interface=%s, netns=%s, pcap_next_ex error: %s",
                         capturer->interface, capturer->netns, pcap_geterr(capturer->p));
            else
                snprintf(capturer->pcap_next_error, ERROR_BUFFER_SIZE,
                         "interface=%s, netns=%s, pcap_next_ex error_code: %d", capturer->interface, capturer->netns,
                         ret);
        }
        break;
    }

    time_t now;
    if (ret == 1)
        now = hdr->ts.tv_sec;
    else
        now = time(NULL);

    // drop stat
    if (!capturer->drop_stat_started)
    {
        struct pcap_stat stat;
        if (pcap_stats(capturer->p, &stat) == 0)
        {
            capturer->drop_stat_started = true;
            capturer->prev_ps_drop = stat.ps_drop;
            capturer->prev_ps_ifdrop = stat.ps_ifdrop;
            capturer->drop_stat_prev_time = now;
        }

        return num_pkts;
    }

    if (difftime(now, capturer->drop_stat_prev_time) < DROP_STAT_DUR_SEC)
        return num_pkts;

    struct pcap_stat stat;
    if (pcap_stats(capturer->p, &stat) == 0)
    {
        u_int drop_diff = stat.ps_drop - capturer->prev_ps_drop;
        packets_stats_add(&capturer->base.stats->drop_packets, drop_diff);

        u_int ifdrop_diff = stat.ps_ifdrop - capturer->prev_ps_ifdrop;
        packets_stats_add(&capturer->base.stats->ifdrop_packets, ifdrop_diff);

        capturer->prev_ps_drop = stat.ps_drop;
        capturer->prev_ps_ifdrop = stat.ps_ifdrop;
        capturer->drop_stat_prev_time = now;
    }

    if (capturer->pcap_next_error[0] != '\0')
    {
        log_error(capturer->pcap_next_error);
        capturer->pcap_next_error[0] = '\0';
    }
    return num_pkts;
}

libpcap_capturer_t *libpcap_capturer_new(libpcap_options_t opts, capture_stats_t *stats, char *errbuf)
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
    pcap_set_promisc(p, opts.promisc);
    pcap_set_buffer_size(p, opts.buffer_size);

    // TPACKET_V3 (libpcap on modern Linux) delivers packets to userspace one *block* at a
    // time; a block only becomes visible once it fills or its kernel retire timer
    // (tp_retire_blk_tov, taken from the pcap timeout) fires. This only bites when
    // timeout_ms == 0: libpcap then sets tp_retire_blk_tov = UINT_MAX, so a block is
    // effectively delivered only when full -- at low/bursty rates that takes seconds
    // (measured ~0.5-0.9s at 2pps, tens of seconds near-idle), making zmq batches arrive in
    // multi-second bursts. When timeout_ms > 0 the retire timer is already bounded by the
    // user-chosen value, so the problem does not exist and we must NOT override that intent
    // (a non-zero timeout often means "batch up to N ms to save wakeups").
    if (opts.timeout_ms == 0)
    {
        // Non-blocking round-robin path (see pcap_setnonblock below). Immediate mode is the
        // real fix: in libpcap 1.9.x it makes pcap drop TPACKET_V3 and use TPACKET_V2, which
        // delivers per frame with no block buffering (measured ~0ms on ARM/libpcap 1.9.1).
        // It is orthogonal to non-blocking: non-blocking only governs whether a quiet
        // interface returns at once; immediate mode governs when packets become visible.
        // The symbol is weak, so it is NULL when the runtime libpcap is < 1.5.0; guard it.
        int immediate_ok = 0;
        if (pcap_set_immediate_mode)
        {
            int rc_imm = pcap_set_immediate_mode(p, 1);
            if (rc_imm == 0)
                immediate_ok = 1;
            else
                log_warn("pcap_set_immediate_mode failed (rc=%d); falling back to retire-timeout backstop", rc_imm);
        }
        else
        {
            log_info("pcap_set_immediate_mode unavailable in runtime libpcap (<1.5.0); using retire-timeout backstop");
        }

        // Backstop ONLY when immediate mode could not be enabled: bound the TPACKET_V3 retire
        // timer (a 0 timeout would otherwise mean UINT_MAX). When immediate mode IS enabled we
        // leave the timeout alone -- libpcap is on TPACKET_V2 (or, on newer libpcap, drives
        // the retire timer itself), so forcing a 10ms timeout here would be dead at best and
        // could cap delivery at 10ms at worst. (< 1.5.0 libpcap uses TPACKET_V2 anyway.)
        // see: https://github.com/the-tcpdump-group/libpcap/issues/572#issuecomment-576039197
        if (!immediate_ok)
            pcap_set_timeout(p, 10);
    }
    else
    {
        // Blocking path: the user-chosen timeout bounds both the poll wait and the V3 block
        // retire timer; respect it.
        pcap_set_timeout(p, opts.timeout_ms);
    }

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
            pcap_freecode(&bpf_prog);
            goto error;
        }
        pcap_freecode(&bpf_prog);
    }

    if (has_netns)
    {
        int ret = enter_netns_by_fd(self_netns_fd, errbuf);
        close_netns_fd(self_netns_fd);
        if (ret != 0)
            goto error3;
    }

    libpcap_capturer_t *capturer = (libpcap_capturer_t *)calloc(1, sizeof(libpcap_capturer_t));
    if (!capturer)
    {
        error_format(errbuf, "failed to allocate memory for libpcap_capturer_t");
        goto error3;
    }
    capturer->interface = strdup(opts.interface);
    if (!capturer->interface)
    {
        error_format(errbuf, "failed to allocate memory");
        goto error3;
    }
    capturer->netns = strdup(opts.netns);
    if (!capturer->netns)
    {
        error_format(errbuf, "failed to allocate memory");
        goto error3;
    }
    capturer->base.capture = libpcap_do_capture;
    capturer->base.destory = libpcap_capturer_destory;
    capturer->base.stats = stats;

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
    if (capturer)
    {
        free(capturer->netns);
        free(capturer->interface);
        free(capturer);
    }
    pcap_close(p);
    req_pattern_destory(req_pattern);
    return NULL;
}

capturer_base_t *libpcap_capture_new_from_cfg(TasksAllConfig *tasks_cfg, TaskConfig *task_cfg, capture_stats_t *stats,
                                              char *errbuf)
{
    char *bpf_filter = NULL;
    if (!task_cfg->capturer.config.libpcap.not_filter_output_hosts)
    {
        log_info("exclude task output hosts");
        bpf_filter =
            bpf_filter_exclude_task_output_hosts(task_cfg->capturer.config.libpcap.bpf_filter, tasks_cfg, errbuf);
        if (bpf_filter == NULL)
            return NULL;
    }
    else
    {
        bpf_filter = strdup(task_cfg->capturer.config.libpcap.bpf_filter);
        if (bpf_filter == NULL)
        {
            error_format(errbuf, "failed to allocate memory for bpf_filter");
            return NULL;
        }
    }

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
        .interface = task_cfg->capturer.config.libpcap.interface,
        .snaplen = task_cfg->capturer.config.libpcap.snaplen,
        .timeout_ms = task_cfg->capturer.config.libpcap.timeout_ms,
        .promisc = 0,
        .buffer_size = buffer_size,
        .bpf_filter = bpf_filter,
        .netns = task_cfg->capturer.config.libpcap.netns,
        .req_pattern = task_cfg->req_pattern,
    };
    log_info("libpcap capturer options: interface=%s, snaplen=%d, timeout_ms=%d, buffer_size=%d, bpf_filter='%s', "
             "netns='%s'",
             opts.interface, opts.snaplen, opts.timeout_ms, opts.buffer_size, opts.bpf_filter, opts.netns);

    capturer_base_t *capturer = (capturer_base_t *)libpcap_capturer_new(opts, stats, errbuf);
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
    free(capturer->interface);
    free(capturer->netns);
    free(capturer);
}