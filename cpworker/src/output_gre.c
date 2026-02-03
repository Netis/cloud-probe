#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "config.h"
#include "errorf.h"
#include "gre.h"
#include "log.h"
#include "output_gre.h"
#include "pkt_dir.h"
#include "stats.h"

#define ERROR_INFO_FLUSH_MAX_DUR_SEC 5

static void flush_error_info(gre_output_t *output)
{
    output->error_info.first_pktsec = 0;

    if (output->error_info.nb_nobufs_drops > 0 || output->error_info.nb_partial_sends > 0 ||
        output->error_info.nb_other_send_error_drops > 0)
    {
        log_error("gre output error: nb_nobufs_drops=%lu, nb_partial_sends=%lu, nb_other_send_error_drops=%lu, "
                  "detail: %s",
                  output->error_info.nb_nobufs_drops, output->error_info.nb_partial_sends,
                  output->error_info.nb_other_send_error_drops, output->error_info.other_send_error);

        output->error_info.nb_nobufs_drops = 0;
        output->error_info.nb_partial_sends = 0;
        output->error_info.nb_other_send_error_drops = 0;

        output->error_info.other_send_error[0] = '\0';
    }
}

int gre_send_packet(output_base_t *self, const struct pcap_pkthdr *header, const uint8_t *pkt_data, int direct)
{
    gre_output_t *output = (gre_output_t *)self;

    int32_t caplen = header->caplen;
    if (output->slice > 0 && output->slice < caplen)
    {
        caplen = output->slice;
    }

    size_t length = (size_t)(caplen <= 65535 ? caplen : 65535);

    if (direct == PKT_DIR_UNKNOWN)
    {
        bytes_stats_add(&output->base.stats->direction_drop_bytes, length);
        packets_stats_add(&output->base.stats->direction_drop_packets, 1);
        return -1;
    }

    if (output->rate_limit_mbps > 0)
    {
        if (!token_bucket_consume(&output->throttle, GRE_HEADER_LEN + length, header->ts))
        {
            bytes_stats_add(&output->base.stats->ratelimit_drop_bytes, GRE_HEADER_LEN + length);
            packets_stats_add(&output->base.stats->ratelimit_drop_packets, 1);
            return -1;
        }
    }

    struct gre_header *gre_hdr = (struct gre_header *)output->buf;
    gre_hdr->keybit = htonl(output->service_tag | (direct << 28));
    memcpy(&(output->buf[GRE_HEADER_LEN]), pkt_data, length);

    // check error_info
    if (output->error_info.first_pktsec == 0)
        output->error_info.first_pktsec = header->ts.tv_sec;
    else if (header->ts.tv_sec > output->error_info.first_pktsec + ERROR_INFO_FLUSH_MAX_DUR_SEC)
    {
        flush_error_info(output);
        output->error_info.first_pktsec = header->ts.tv_sec;
    }

    int retry_count = 0;
    const int max_retries = 10;
    do
    {
        ssize_t send_bytes = sendto(output->socket_fd, output->buf, GRE_HEADER_LEN + length, 0,
                                    (struct sockaddr *)&output->remote_addr, sizeof(struct sockaddr_in));

        if (send_bytes == -1)
        {
            // retry if errno == ENOBUFS
            if (errno == ENOBUFS && retry_count < max_retries)
            {
                int duration = 100 + retry_count * 200;
                if (duration > 1000)
                {
                    duration = 1000;
                }
                usleep(duration);
                retry_count++;
                continue;
            }

            if (errno == ENOBUFS)
                output->error_info.nb_nobufs_drops++;
            else
            {
                if (output->error_info.nb_other_send_error_drops == 0)
                    snprintf(output->error_info.other_send_error, ERROR_BUFFER_SIZE, "%s", strerror(errno));

                output->error_info.nb_other_send_error_drops++;
            }

            bytes_stats_add(&output->base.stats->error_drop_bytes, GRE_HEADER_LEN + length);
            packets_stats_add(&output->base.stats->error_drop_packets, 1);
            return -1;
        }

        if (send_bytes < GRE_HEADER_LEN + length)
        {
            output->error_info.nb_partial_sends++;

            bytes_stats_add(&output->base.stats->error_drop_bytes, GRE_HEADER_LEN + length - send_bytes);
            bytes_stats_add(&output->base.stats->fwd_bytes, send_bytes);
            packets_stats_add(&output->base.stats->fwd_packets, 1);
            return -1;
        }

        bytes_stats_add(&output->base.stats->fwd_bytes, GRE_HEADER_LEN + length);
        packets_stats_add(&output->base.stats->fwd_packets, 1);
        return 0;
    } while (true);
}

gre_output_t *gre_output_new(gre_options_t opts, output_stats_t *stats, char *errbuf)
{

    struct sockaddr_in remote_addr;
    memset(&remote_addr, 0, sizeof(struct sockaddr_in));

    if (inet_pton(AF_INET, opts.host, &remote_addr.sin_addr) != 1)
    {
        error_format(errbuf, "invalid gre host: %s", opts.host);
        return NULL;
    }
    remote_addr.sin_family = AF_INET;

    int socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_GRE);
    if (socket_fd == -1)
    {
        error_format(errbuf, "create socket error: %s", strerror(errno));
        return NULL;
    }

    if (opts.bind_device && strcmp(opts.bind_device, "") != 0)
    {
        if (setsockopt(socket_fd, SOL_SOCKET, SO_BINDTODEVICE, opts.bind_device, strlen(opts.bind_device) + 1) == -1)
        {
            error_format(errbuf, "set SO_BINDTODEVICE for device %s error: %s", opts.bind_device, strerror(errno));
            close(socket_fd);
            return NULL;
        }
    }

#if defined(OS_LINUX)
    if (opts.pmtudisc > 0)
    {
        if (setsockopt(socket_fd, SOL_IP, IP_MTU_DISCOVER, &opts.pmtudisc, sizeof(opts.pmtudisc)) == -1)
        {
            error_format(errbuf, "set IP_MTU_DISCOVER error: %s", strerror(errno));
            close(socket_fd);
            return NULL;
        }
    }
#endif

    gre_output_t *output = (gre_output_t *)calloc(1, sizeof(gre_output_t));
    if (!output)
    {
        error_format(errbuf, "failed to allocate memory for gre_output_t");
        close(socket_fd);
        return NULL;
    }

    struct gre_header gre_hdr;
    gre_hdr.flags = htons(0x2000);    // K = 1
    gre_hdr.protocol = htons(0x6558); // Ethernet over GRE
    gre_hdr.keybit = htonl(opts.service_tag);
    memcpy(output->buf, &gre_hdr, GRE_HEADER_LEN);

    output->base.send_packet = gre_send_packet;
    output->base.heartbeat = NULL;
    output->base.destory = gre_output_destory;
    output->base.stats = stats;

    if (opts.rate_limit_mbps > 0)
    {
        token_bucket_init(&output->throttle, opts.rate_limit_mbps * 1000000);
    }
    output->rate_limit_mbps = opts.rate_limit_mbps;
    output->slice = opts.slice;

    output->service_tag = opts.service_tag;
    output->remote_addr = remote_addr;
    output->socket_fd = socket_fd;
    output->error_info.other_send_error[0] = '\0';

    return output;
}

output_base_t *gre_output_new_from_cfg(TaskConfig *task_cfg, OutputConfig *output_cfg, output_stats_t *stats,
                                       char *errbuf)
{
    gre_options_t opts = {
        .host = output_cfg->config.gre.host,
        .service_tag = output_cfg->config.gre.service_tag,
        .bind_device = output_cfg->config.gre.bind_device,
        .pmtudisc = output_cfg->config.gre.pmtudisc,
        .rate_limit_mbps = output_cfg->rate_limit_mbps,
        .slice = output_cfg->slice,
    };
    log_info("gre output options: host=%s, service_tag=%d, bind_device=%s, pmtudisc=%d, rate_limit_mbps=%d, slice=%d",
             opts.host, opts.service_tag, opts.bind_device, opts.pmtudisc, opts.rate_limit_mbps, opts.slice);
    return (output_base_t *)gre_output_new(opts, stats, errbuf);
}

void gre_output_destory(output_base_t *self)
{
    if (!self)
        return;

    log_info("call gre_output_destory");
    gre_output_t *output = (gre_output_t *)self;

    close(output->socket_fd);
    free(output);
}
