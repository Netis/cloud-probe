#ifndef CPAGENT_TASKCONF_H
#define CPAGENT_TASKCONF_H

#include <stdbool.h>
#include <stdint.h>

#include "cjson_utils.h"

#define CAPTURER_TYPE_DPDK_PDUMP "dpdk_pdump"
#define CAPTURER_TYPE_LIBPCAP "libpcap"

#define REQ_PATTERN_TYPE_AUTO_STR "auto"
#define REQ_PATTERN_TYPE_CUSTOM_STR "custom"
#define REQ_PATTERN_TYPE_NONE_STR "none"

#define OUTPUT_TYPE_VXLAN "vxlan"
#define OUTPUT_TYPE_GRE "gre"
#define OUTPUT_TYPE_ZMQ "zmq"
#define OUTPUT_TYPE_FILE "file"
#define OUTPUT_TYPE_ROTATING_FILE "rotating_file"

#define IP_PMTUDISC_DONT 0  /* Never send DF frames.  */
#define IP_PMTUDISC_WANT 1  /* Use per route hints.  */
#define IP_PMTUDISC_DO 2    /* Always DF.  */
#define IP_PMTUDISC_PROBE 3 /* Ignore dst pmtu.  */

typedef struct
{
    char *type;
    uint64_t rate_limit_mbps;
    int slice;
    union
    {
        struct
        {
            char *host;
            int port;
            bool capture_time;
            uint8_t vni_version;
            uint32_t vni;
            char *bind_device;
            int pmtudisc;
        } vxlan;

        struct
        {
            char *host;
            uint32_t service_tag;
            char *bind_device;
            int pmtudisc;
        } gre;

        struct
        {
            char *host;
            int port;
            int hwm;
            uint32_t service_tag;
        } zmq;

        struct
        {
            char *name;
        } file;

        struct
        {
            char *file_root;
            int max_file_interval;
        } rotating_file;
    } config;
} OutputConfig;

typedef struct
{
    char *type;

    union
    {
        struct
        {
            char *bpf_filter;
            int buffer_size_mb;
            int timeout_ms;
        } libpcap;

        struct
        {
            char *bpf_filter;
            int ring_size;
        } dpdk_pdump;
    } config;
} CapturerConfig;

typedef struct
{
    char *type;
    struct
    {
        char *pattern;
    } custom;
} ReqPatternConfig;

typedef struct
{
    char *interface;
    int snaplen;
    char *netns;

    ReqPatternConfig req_pattern;

    CapturerConfig capturer;

    OutputConfig **outputs;
    int num_outputs;
} TaskConfig;

typedef struct
{
    TaskConfig **tasks;
    int num_tasks;
} TasksAllConfig;

TasksAllConfig *parse_tasks_config(char *data, cJSONParseError *err);
TasksAllConfig *parse_tasks_file(const char *filename, cJSONParseError *err);
void free_tasks_config(TasksAllConfig *config);

#endif /* CPAGENT_TASKCONF_H */
