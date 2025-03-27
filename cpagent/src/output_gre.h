#ifndef CPAGENT_OUTPUT_GRE_H
#define CPAGENT_OUTPUT_GRE_H

#include <netinet/in.h>
#include <stdint.h>

#include "output.h"
#include "ratelimit.h"
#include "taskconf.h"

#define GRE_OUTPUT_BUFSIZE 65551 // 8(GRE_HEADER_LEN) + 65535

typedef struct GreOptions
{
    char *host;
    uint32_t service_tag;
    char *bind_device;
    int pmtudisc;
    uint64_t rate_limit_mbps;

} gre_options_t;

typedef struct GreOutput
{
    output_base_t base;
    output_stats_t stats;

    uint64_t rate_limit_mbps;
    token_bucket_t throttle;

    uint32_t service_tag;
    struct sockaddr_in remote_addr;

    int socket_fd;
    char buf[GRE_OUTPUT_BUFSIZE];
} gre_output_t;

output_base_t *gre_output_new_from_cfg(TaskConfig *task_cfg, OutputConfig *output_cfg, char *errbuf);
gre_output_t *gre_output_new(gre_options_t opts, char *errbuf);
void gre_output_destory(output_base_t *output);

#endif /* CPAGENT_OUTPUT_GRE_H */