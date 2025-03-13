#ifndef CPAGENT_TASKCONF_H
#define CPAGENT_TASKCONF_H

#include "cjson_utils.h"
#include <stdint.h>

#define CAPTURER_ENGINE_DPDK_PDUMP "dpdk_pdump"
#define CAPTURER_ENGINE_LIBPCAP "libpcap"
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
            int capture_time;
            uint8_t version;
            uint32_t vni;
            char *bind_device;
        } vxlan;

        struct
        {
            char *host;
            uint32_t keybit;
            char *bind_device;
        } gre;

        struct
        {
            char *host;
            int port;
            int hwm;
            uint32_t keybit;
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
    char *interface;
    int snaplen;
    char *netns;
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