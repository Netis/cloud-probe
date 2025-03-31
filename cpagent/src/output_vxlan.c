#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "common.h"
#include "error.h"
#include "log.h"
#include "output_vxlan.h"

int vxlan_send_packet(output_base_t *self, const struct pcap_pkthdr *header, const uint8_t *pkt_data, int direct)
{
    vxlan_output_t *output = (vxlan_output_t *)self;

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
        if (token_bucket_consume(&output->throttle, VXLAN_HEADER_LEN + length) != 0)
        {
            bytes_stats_add(&output->base.stats.ratelimit_drop_bytes, VXLAN_HEADER_LEN + length);
            packets_stats_add(&output->base.stats.ratelimit_drop_packets, 1);
            return -1;
        }
    }

    struct vxlanhdr *vxlan_hdr = (struct vxlanhdr *)output->buf;
    memcpy(&(output->buf[VXLAN_HEADER_LEN]), pkt_data, length);

    uint32_t tv_sec = htonl(header->ts.tv_sec);
    // 注意：通过libpcap获取的捕获时间精度为微秒，而数据包中附加的时间为纳秒，所以需要*1000
    uint32_t tv_nsec = htonl(header->ts.tv_usec * 1000);
    if (output->capture_time)
    {
        memcpy(&(output->buf[VXLAN_HEADER_LEN + length]), &tv_sec, 4);
        length += 4;
        memcpy(&(output->buf[VXLAN_HEADER_LEN + length]), &tv_nsec, 4);
        length += 4;
    }
    if (output->vni_version == 1)
    {
        vxlan_hdr->vx_vni = htonl(output->vni << 8);
        if (direct != PKT_DIR_NONCHECK)
        {
            ((pa_tag_t *)&vxlan_hdr->vx_vni)->rra = direct;
            ((pa_tag_t *)&vxlan_hdr->vx_vni)->reserved1 = 0;
            ((pa_tag_t *)&vxlan_hdr->vx_vni)->reserved2 = 0;
            ((pa_tag_t *)&vxlan_hdr->vx_vni)->check = 0;
        }
        // TODO: add check sum
    }
    else
    {
        vxlan_hdr->vx_vni = htonl(output->vni + direct);
    }

    ssize_t send_bytes = sendto(output->socket_fd, output->buf, VXLAN_HEADER_LEN + length, 0,
                                (struct sockaddr *)&output->remote_addr, sizeof(struct sockaddr_in));

    // TODO: retry if errno == ENOBUFS
    if (send_bytes == -1)
    {
        return -1;
    }
    return 0;
}

vxlan_output_t *vxlan_output_new(vxlan_options_t opts, char *errbuf)
{
    struct sockaddr_in remote_addr;
    memset(&remote_addr, 0, sizeof(struct sockaddr_in));

    if (inet_pton(AF_INET, opts.host, &remote_addr.sin_addr) != 1)
    {
        error_format("invalid vxlan host: %s", opts.host);
        return NULL;
    }
    remote_addr.sin_family = AF_INET;
    remote_addr.sin_port = htons(opts.port);

    int socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
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

    if (opts.pmtudisc > 0)
    {
        if (setsockopt(socket_fd, SOL_IP, IP_MTU_DISCOVER, &opts.pmtudisc, sizeof(opts.pmtudisc)) == -1)
        {
            error_format(errbuf, "set IP_MTU_DISCOVER error: %s", strerror(errno));
            return NULL;
        }
    }

    vxlan_output_t *output = (vxlan_output_t *)calloc(1, sizeof(vxlan_output_t));
    if (!output)
    {
        error_format(errbuf, "failed to allocate memory for vxlan_output_t");
        return NULL;
    }

    struct vxlanhdr vxlan_hdr;
    vxlan_hdr.vx_flags = htonl(0x08000000);
    vxlan_hdr.vx_vni = (htonl(opts.vni << 8));
    memcpy(output->buf, &vxlan_hdr, VXLAN_HEADER_LEN);

    output->base.send_packet = vxlan_send_packet;
    output->base.destory = vxlan_output_destory;

    if (opts.rate_limit_mbps > 0)
    {
        token_bucket_init(&output->throttle, opts.rate_limit_mbps * 1000000);
    }
    output->rate_limit_mbps = opts.rate_limit_mbps;
    output->slice = opts.slice,

    output->vni_version = opts.vni_version;
    output->vni = opts.vni;
    output->capture_time = opts.capture_time;
    output->remote_addr = remote_addr;
    output->socket_fd = socket_fd;
    return output;
}

output_base_t *vxlan_output_new_from_cfg(TaskConfig *task_cfg, OutputConfig *output_cfg, char *errbuf)
{
    vxlan_options_t opts = {
        .host = output_cfg->config.vxlan.host,
        .port = output_cfg->config.vxlan.port,
        .capture_time = output_cfg->config.vxlan.capture_time,
        .vni_version = output_cfg->config.vxlan.vni_version,
        .vni = output_cfg->config.vxlan.vni,
        .bind_device = output_cfg->config.vxlan.bind_device,
        .pmtudisc = output_cfg->config.vxlan.pmtudisc,
        .rate_limit_mbps = output_cfg->rate_limit_mbps,
        .slice = output_cfg->slice,
    };
    return (output_base_t *)vxlan_output_new(opts, errbuf);
}

void vxlan_output_destory(output_base_t *self)
{
    if (!self)
        return;

    log_info("call vxlan_output_destory");
    vxlan_output_t *output = (vxlan_output_t *)self;

    close(output->socket_fd);
    free(output);
}
