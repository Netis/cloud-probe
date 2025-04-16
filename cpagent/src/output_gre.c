#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "error.h"
#include "gre.h"
#include "log.h"
#include "output_gre.h"
#include "pkt_dir.h"
#include "stats.h"
#include "taskconf.h"

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
        bytes_stats_add(&output->base.stats.direction_drop_bytes, length);
        packets_stats_add(&output->base.stats.direction_drop_packets, 1);
        return -1;
    }

    if (output->rate_limit_mbps > 0)
    {
        if (token_bucket_consume(&output->throttle, GRE_HEADER_LEN + length) != 0)
        {
            bytes_stats_add(&output->base.stats.ratelimit_drop_bytes, length);
            packets_stats_add(&output->base.stats.ratelimit_drop_packets, 1);
            return -1;
        }
    }

    struct grehdr *gre_hdr = (struct grehdr *)output->buf;
    gre_hdr->keybit = htonl(output->service_tag | (direct << 28));
    memcpy(&(output->buf[GRE_HEADER_LEN]), pkt_data, length);

    ssize_t send_bytes = sendto(output->socket_fd, output->buf, GRE_HEADER_LEN + length, 0,
                                (struct sockaddr *)&output->remote_addr, sizeof(struct sockaddr_in));

    // TODO: retry if errno == ENOBUFS
    if (send_bytes == -1)
    {
        bytes_stats_add(&output->base.stats.error_drop_bytes, length);
        packets_stats_add(&output->base.stats.error_drop_packets, 1);
        return -1;
    }

    bytes_stats_add(&output->base.stats.fwd_bytes, length);
    packets_stats_add(&output->base.stats.fwd_packets, 1);
    return 0;
}

gre_output_t *gre_output_new(gre_options_t opts, char *errbuf)
{

    struct sockaddr_in remote_addr;
    memset(&remote_addr, 0, sizeof(struct sockaddr_in));

    if (inet_pton(AF_INET, opts.host, &remote_addr.sin_addr) != 1)
    {
        error_format("invalid gre host: %s", opts.host);
        return NULL;
    }
    remote_addr.sin_family = AF_INET;

    int socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_GRE);
    if (socket_fd == -1)
    {
        error_format("create socket error: %s", strerror(errno));
        return NULL;
    }

    if (opts.bind_device && strcmp(opts.bind_device, "") != 0)
    {
        if (setsockopt(socket_fd, SOL_SOCKET, SO_BINDTODEVICE, opts.bind_device, strlen(opts.bind_device) + 1) == -1)
        {
            error_format(errbuf, "set SO_BINDTODEVICE for device %s error: %s", opts.bind_device, strerror(errno));
            return NULL;
        }
    }

#if defined(OS_LINUX)
    if (opts.pmtudisc > 0)
    {
        if (setsockopt(socket_fd, SOL_IP, IP_MTU_DISCOVER, &opts.pmtudisc, sizeof(opts.pmtudisc)) == -1)
        {
            error_format(errbuf, "set IP_MTU_DISCOVER error: %s", strerror(errno));
            return NULL;
        }
    }
#endif

    gre_output_t *output = (gre_output_t *)calloc(1, sizeof(gre_output_t));
    if (!output)
    {
        error_format(errbuf, "failed to allocate memory for gre_output_t");
        return NULL;
    }

    struct grehdr gre_hdr;
    gre_hdr.flags = htons(0x2000);    // K = 1
    gre_hdr.protocol = htons(0x6558); // Ethernet over GRE
    gre_hdr.keybit = htonl(opts.service_tag);
    memcpy(output->buf, &gre_hdr, GRE_HEADER_LEN);

    output->base.send_packet = gre_send_packet;
    output->base.destory = gre_output_destory;

    if (opts.rate_limit_mbps > 0)
    {
        token_bucket_init(&output->throttle, opts.rate_limit_mbps * 1000000);
    }
    output->rate_limit_mbps = opts.rate_limit_mbps;
    output->slice = opts.slice;

    output->service_tag = opts.service_tag;
    output->remote_addr = remote_addr;
    output->socket_fd = socket_fd;

    return output;
}

output_base_t *gre_output_new_from_cfg(TaskConfig *task_cfg, OutputConfig *output_cfg, char *errbuf)
{
    gre_options_t opts = {
        .host = output_cfg->config.gre.host,
        .service_tag = output_cfg->config.gre.service_tag,
        .bind_device = output_cfg->config.gre.bind_device,
        .pmtudisc = output_cfg->config.gre.pmtudisc,
        .rate_limit_mbps = output_cfg->rate_limit_mbps,
        .slice = output_cfg->slice,
    };
    return (output_base_t *)gre_output_new(opts, errbuf);
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
