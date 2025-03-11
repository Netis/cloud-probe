#ifndef CPAGENT_TASKCONF_H
#define CPAGENT_TASKCONF_H

#include "cjson_utils.h"
#include <stdint.h>

typedef struct
{
    char *type;

    // 公共字段
    int rate_limit_mbps;
    int slice;

    // 不同导出类型的配置
    union
    {
        struct
        {
            char **remote_ips;
            int remote_ip_count;
            int port;
            int capture_time;
            uint8_t version;
            uint32_t vni;
            char *bind_device;
        } vxlan;

        struct
        {
            char **remote_ips;
            int remote_ip_count;
            int keybit;
            char *bind_device;
        } gre;

        struct
        {
            char **remote_ips;
            int remote_ip_count;
            int port;
            int hwm;
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
    OutputConfig output;
} TaskConfig;

typedef struct
{
    TaskConfig **tasks;
    int num_tasks;
} TaskSetConfig;

TaskSetConfig *parse_tasks_config(char *data, cJSONParseError *err);
TaskSetConfig *parse_tasks_file(const char *filename, cJSONParseError *err);
void free_tasks_config(TaskSetConfig *config);

#endif /* CPAGENT_TASKCONF_H */