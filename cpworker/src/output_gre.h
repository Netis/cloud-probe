#ifndef CPWORKER_OUTPUT_GRE_H
#define CPWORKER_OUTPUT_GRE_H

#include <netinet/in.h>
#include <stdint.h>

#include "config.h"
#include "errorf.h"
#include "output.h"
#include "ratelimit.h"

#define GRE_OUTPUT_BUFSIZE 65551 // 8(GRE_HEADER_LEN) + 65535

typedef struct GreOptions
{
    char *host;
    uint32_t service_tag;
    char *bind_device;
    int pmtudisc;
    uint64_t rate_limit_mbps;
    int slice;

} gre_options_t;

typedef struct GreOutput
{
    output_base_t base;

    uint64_t rate_limit_mbps;
    token_bucket_t throttle;
    int slice;

    uint32_t service_tag;
    struct sockaddr_in remote_addr;

    int socket_fd;
    char buf[GRE_OUTPUT_BUFSIZE];

    struct
    {
        long int first_pktsec;
        uint64_t nb_nobufs_drops;
        uint64_t nb_partial_sends;
        uint64_t nb_other_send_error_drops;
        char other_send_error[ERROR_BUFFER_SIZE];
    } error_info;
} gre_output_t;

output_base_t *gre_output_new_from_cfg(TaskConfig *task_cfg, OutputConfig *output_cfg, output_stats_t *stats,
                                       char *errbuf);
gre_output_t *gre_output_new(gre_options_t opts, output_stats_t *stats, char *errbuf);
void gre_output_destroy(output_base_t *output);

#endif /* CPWORKER_OUTPUT_GRE_H */