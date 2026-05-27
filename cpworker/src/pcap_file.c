#include <stdlib.h>
#include <string.h>

#include <pcap/pcap.h>

#include "bpf_util.h"
#include "errorf.h"
#include "log.h"
#include "pcap_file.h"
#include "pkt_dir.h"

uint64_t pcap_file_do_capture(capturer_base_t *self, capture_packet_handler pkt_handler,
                              capture_heartbeat_handler heartbeat_handler, void *user)
{
    pcap_file_capturer_t *capturer = (pcap_file_capturer_t *)self;

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
    default:
        if (ret == PCAP_ERROR_BREAK)
        {
            heartbeat_handler(user);
            if (!capturer->eof)
            {
                log_info("end of file");
                capturer->eof = true;
            }
        }
        break;
    }
    return num_pkts;
}

pcap_file_capturer_t *pcap_file_capturer_new(pcap_file_options_t opts, capture_stats_t *stats, char *errbuf)
{
    req_pattern_t *req_pattern = req_pattern_new_from_cfg(opts.req_pattern, "", errbuf);
    if (!req_pattern)
    {
        error_wrap_format(errbuf, "create req_pattern_t error");
        return NULL;
    }

    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *p = pcap_open_offline(opts.file_name, error_buffer);
    if (p == NULL)
    {
        error_format(errbuf, "could not load file %s: %s", opts.file_name, error_buffer);
        req_pattern_destory(req_pattern);
        return NULL;
    }

    int snaplen = pcap_snapshot(p);
    log_info("pcap file snaplen is %d", snaplen);

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

    pcap_file_capturer_t *capturer = (pcap_file_capturer_t *)calloc(1, sizeof(pcap_file_capturer_t));
    if (!capturer)
    {
        error_format(errbuf, "failed to allocate memory for pcap_file_capturer_t");
        goto error;
    }
    capturer->base.capture = pcap_file_do_capture;
    capturer->base.destory = pcap_file_capturer_destory;
    capturer->base.stats = stats;
    capturer->req_pattern = req_pattern;
    capturer->p = p;
    return capturer;
error:
    pcap_close(p);
    req_pattern_destory(req_pattern);
    return NULL;
}

capturer_base_t *pcap_file_capture_new_from_cfg(TasksAllConfig *tasks_cfg, TaskConfig *task_cfg, capture_stats_t *stats,
                                                char *errbuf)
{
    char *bpf_filter =
        bpf_filter_exclude_task_output_hosts(task_cfg->capturer.config.pcap_file.bpf_filter, tasks_cfg, errbuf);
    if (bpf_filter == NULL)
        return NULL;

    pcap_file_options_t opts = {
        .file_name = task_cfg->capturer.config.pcap_file.file_name,
        .bpf_filter = bpf_filter,
        .req_pattern = task_cfg->req_pattern,
    };
    log_info("pcap_file capturer options: file_name=%s, bpf_filter='%s'", opts.file_name, opts.bpf_filter);

    capturer_base_t *capturer = (capturer_base_t *)pcap_file_capturer_new(opts, stats, errbuf);
    free(bpf_filter);
    return capturer;
}

void pcap_file_capturer_destory(capturer_base_t *self)
{
    if (!self)
        return;

    pcap_file_capturer_t *capturer = (pcap_file_capturer_t *)self;

    log_info("free pcap_file capturer");
    req_pattern_destory(capturer->req_pattern);
    pcap_close(capturer->p);
    free(capturer);
}