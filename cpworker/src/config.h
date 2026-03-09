#ifndef CPWORKER_CONFIG_H
#define CPWORKER_CONFIG_H

#include <stdbool.h>
#include <stdint.h>

#include "cjson_utils.h"

#define CAPTURER_TYPE_DPDK_PDUMP "dpdk_pdump"
#define CAPTURER_TYPE_LIBPCAP "libpcap"
#define CAPTURER_TYPE_PCAP_FILE "pcap_file"

#define REQ_PATTERN_TYPE_AUTO_STR "auto"
#define REQ_PATTERN_TYPE_CUSTOM_STR "custom"
#define REQ_PATTERN_TYPE_NONE_STR "none"

#define OUTPUT_TYPE_VXLAN "vxlan"
#define OUTPUT_TYPE_GRE "gre"
#define OUTPUT_TYPE_ZMQ "zmq"
#define OUTPUT_TYPE_FILE "file"
#define OUTPUT_TYPE_ROTATING_FILE "rotating_file"
#define OUTPUT_TYPE_NULL "null"

#define IP_PMTUDISC_DONT 0  /* Never send DF frames.  */
#define IP_PMTUDISC_WANT 1  /* Use per route hints.  */
#define IP_PMTUDISC_DO 2    /* Always DF.  */
#define IP_PMTUDISC_PROBE 3 /* Ignore dst pmtu.  */

#define CONTROL_TYPE_UNIX "unix"

typedef struct
{
    uint16_t max_payload_size;      // 0 = disabled
    bool recalculate_checksum;      // Whether to recalculate checksums after splitting (default: false)
} SplitConfig;

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
            uint16_t port;
            bool capture_time;
            uint8_t vni_version;
            uint32_t vni;
            char *bind_device;
            int pmtudisc;
            SplitConfig split;
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
            uint16_t port;
            int hwm;
            uint32_t service_tag;
            char *uuid;
            int heartbeat_ms;
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
            char *interface;
            int snaplen;
            char *netns;
            char *bpf_filter;
            int buffer_size_mb;
            int timeout_ms;
            bool not_filter_output_hosts;
        } libpcap;

        struct
        {
            char *file_name;
            char *bpf_filter;
        } pcap_file;

        struct
        {
            char *interface;
            int snaplen;
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

typedef struct
{
    char *type;
    union
    {
        struct
        {
            char *path;
        } unix_socket;
    } config;
} ControlConfig;

typedef struct
{
    int log_level;
    char *cpu_affinity;
    ControlConfig *control;
    TasksAllConfig *tasks_cfg;
} Config;

TasksAllConfig *parse_tasks_file(const char *filename, cJSONParseError *err);
void free_tasks_config(TasksAllConfig *config);

Config *parse_config_file(const char *filename, cJSONParseError *err);
Config *parse_config_data(const char *json_str, cJSONParseError *err);
void free_config(Config *config);

char *bpf_filter_exclude_task_output_hosts(const char *bpf, TaskConfig *task_cfg, char *errbuf);
int task_capturer_snaplen(TaskConfig *task_cfg);

#endif /* CPWORKER_CONFIG_H */
