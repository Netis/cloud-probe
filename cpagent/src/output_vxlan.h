#ifndef CPAGENT_OUTPUT_VXLAN_H
#define CPAGENT_OUTPUT_VXLAN_H

#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>

#include "output.h"
#include "ratelimit.h"
#include "taskconf.h"

#define VXLAN_OUTPUT_BUFSIZE 65551 // 8(VXLAN_HEADER_LEN) + 65535 + 8(capture_time)

typedef struct VxlanOptions
{
    char *host;
    int port;
    bool capture_time;
    uint8_t vni_version;
    uint32_t vni;
    char *bind_device;
    int pmtudisc;
    uint64_t rate_limit_mbps;
    int slice;

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
} vxlan_output_t;

output_base_t *vxlan_output_new_from_cfg(TaskConfig *task_cfg, OutputConfig *output_cfg, char *errbuf);
vxlan_output_t *vxlan_output_new(vxlan_options_t opts, char *errbuf);
void vxlan_output_destory(output_base_t *output);

#endif /* CPAGENT_OUTPUT_VXLAN_H */