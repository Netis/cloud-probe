#include <arpa/inet.h>
#include <errno.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "errorf.h"
#include "ip.h"
#include "log.h"
#include "output_vxlan.h"
#include "pkt_dir.h"
#include "stats.h"
#include "vxlan.h"

typedef struct
{
    uint8_t reserved1 : 4;
    uint8_t rra : 4;
    uint8_t service_tag_h : 4;
    uint8_t reserved2 : 4;
    uint8_t service_tag_l : 8;
    uint8_t check;
} pa_tag_t;

static inline uint32_t __rte_raw_cksum(const void *buf, size_t len, uint32_t sum)
{
    /* workaround gcc strict-aliasing warning */
    uintptr_t ptr = (uintptr_t)buf;
    typedef uint16_t u16_p;
    const u16_p *u16 = (const u16_p *)ptr;

    while (len >= (sizeof(*u16) * 4))
    {
        sum += u16[0];
        sum += u16[1];
        sum += u16[2];
        sum += u16[3];
        len -= sizeof(*u16) * 4;
        u16 += 4;
    }
    while (len >= sizeof(*u16))
    {
        sum += *u16;
        len -= sizeof(*u16);
        u16 += 1;
    }

    /* if length is in odd bytes */
    if (len == 1)
        sum += *((const uint8_t *)u16);

    return sum;
}

static inline uint16_t __rte_raw_cksum_reduce(uint32_t sum)
{
    sum = ((sum & 0xffff0000) >> 16) + (sum & 0xffff);
    sum = ((sum & 0xffff0000) >> 16) + (sum & 0xffff);
    return (uint16_t)sum;
}

static inline uint16_t rte_raw_cksum(const void *buf, size_t len)
{
    uint32_t sum;

    sum = __rte_raw_cksum(buf, len, 0x4a3b2d1c);
    return __rte_raw_cksum_reduce(sum);
}

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

    struct vxlan_header *vxlan_hdr = (struct vxlan_header *)output->buf;
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
        // CheckSum
        ((pa_tag_t *)&vxlan_hdr->vx_vni)->check = (uint8_t)rte_raw_cksum(
            vxlan_hdr, sizeof(struct vxlan_header) + sizeof(struct ether_header) + sizeof(struct ipv4_hdr));
    }
    else
    {
        vxlan_hdr->vx_vni = htonl(output->vni + direct);
    }

    int retry_count = 0;
    const int max_retries = 10;
    do
    {
        ssize_t send_bytes = sendto(output->socket_fd, output->buf, VXLAN_HEADER_LEN + length, 0,
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

            // TODO: log error
            bytes_stats_add(&output->base.stats.error_drop_bytes, VXLAN_HEADER_LEN + length);
            packets_stats_add(&output->base.stats.error_drop_packets, 1);
            return -1;
        }

        if (send_bytes < VXLAN_HEADER_LEN + length)
        {
            // TODO: log warning about partial send
            bytes_stats_add(&output->base.stats.error_drop_bytes, VXLAN_HEADER_LEN + length - send_bytes);
            bytes_stats_add(&output->base.stats.fwd_bytes, send_bytes);
            packets_stats_add(&output->base.stats.fwd_packets, 1);
            return -1;
        }

        bytes_stats_add(&output->base.stats.fwd_bytes, VXLAN_HEADER_LEN + length);
        packets_stats_add(&output->base.stats.fwd_packets, 1);
        return 0;
    } while (true);
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

    vxlan_output_t *output = (vxlan_output_t *)calloc(1, sizeof(vxlan_output_t));
    if (!output)
    {
        error_format(errbuf, "failed to allocate memory for vxlan_output_t");
        return NULL;
    }

    struct vxlan_header vxlan_hdr;
    vxlan_hdr.vx_flags = htonl(0x08000000);
    vxlan_hdr.vx_vni = (htonl(opts.vni << 8));
    memcpy(output->buf, &vxlan_hdr, VXLAN_HEADER_LEN);

    output->base.send_packet = vxlan_send_packet;
    output->base.heartbeat = NULL;
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
    log_info("vxlan output options: host=%s, port=%d, capture_time=%d, vni_version=%d, vni=%d, bind_device=%s, "
             "pmtudisc=%d, rate_limit_mbps=%d, slice=%d",
             opts.host, opts.port, opts.capture_time, opts.vni_version, opts.vni, opts.bind_device, opts.pmtudisc,
             opts.rate_limit_mbps, opts.slice);
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
