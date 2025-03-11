#ifndef CPAGENT_TASKCONF_H
#define CPAGENT_TASKCONF_H

#include "cjson_utils.h"
#include <stdint.h>

typedef struct
{
    char *type;
    int rate_limit_mbps;
    int slice;
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
    } config;
} OutputConfig;

typedef struct
{
    char *type;

    union
    {
        struct
        {
            int snaplen;
            char *bpf_filter;
            int buffer_size_mb;
            int timeout_ms;
        } libpcap;

        struct
        {
            int snaplen;
            char *bpf_filter;
            int ring_size;
        } dpdkdump;
    } config;
} EngineConfig;

typedef struct
{
    char *interface;
    char *netns;
    EngineConfig engine;

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