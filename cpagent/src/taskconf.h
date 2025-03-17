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

typedef struct
{
    char *type;
    int rate_limit_mbps;
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
        } vxlan;

        struct
        {
            char *host;
            uint32_t service_tag;
            char *bind_device;
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
        char **patterns;
        int num_patterns;
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
