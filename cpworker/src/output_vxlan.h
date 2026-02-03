#ifndef CPWORKER_OUTPUT_VXLAN_H
#define CPWORKER_OUTPUT_VXLAN_H

#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>

#include "config.h"
#include "errorf.h"
#include "output.h"
#include "ratelimit.h"

#define VXLAN_OUTPUT_BUFSIZE 65551 // 8(VXLAN_HEADER_LEN) + 65535 + 8(capture_time)

typedef struct VxlanOptions
{
    char *host;
    uint16_t port;
    bool capture_time;
    uint8_t vni_version;
    uint32_t vni;
    char *bind_device;
    int pmtudisc;
    uint64_t rate_limit_mbps;
    int slice;

    // Packet splitting options
    struct
    {
        uint16_t max_payload_size;
        bool recalculate_checksum;  // Whether to recalculate checksums after splitting (default: false)
    } split;
} vxlan_options_t;

typedef struct VxlanOutput
{
    output_base_t base;

    uint64_t rate_limit_mbps;
    token_bucket_t throttle;
    int slice;

    uint8_t vni_version;
    uint32_t vni;
    bool capture_time;
    struct sockaddr_in remote_addr;

    int socket_fd;
    char buf[VXLAN_OUTPUT_BUFSIZE];

    // Packet splitting state
    struct
    {
        uint16_t max_payload_size;
        bool recalculate_checksum;
        uint8_t fragment_buf[VXLAN_OUTPUT_BUFSIZE];
    } split;

    struct
    {
        long int first_pktsec;
        uint64_t nb_nobufs_drops;
        uint64_t nb_partial_sends;
        uint64_t nb_other_send_error_drops;
        char other_send_error[ERROR_BUFFER_SIZE];
    } error_info;
} vxlan_output_t;

output_base_t *vxlan_output_new_from_cfg(TaskConfig *task_cfg, OutputConfig *output_cfg, output_stats_t *stats,
                                         char *errbuf);
vxlan_output_t *vxlan_output_new(vxlan_options_t opts, output_stats_t *stats, char *errbuf);
void vxlan_output_destory(output_base_t *output);

#endif /* CPWORKER_OUTPUT_VXLAN_H */