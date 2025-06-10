#include <net/ethernet.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "capturer.h"
#include "config.h"
#include "errorf.h"
#include "libpcap.h"
#include "log.h"
#include "output_file.h"
#include "output_gre.h"
#include "output_null.h"
#include "output_rotating_file.h"
#include "output_vxlan.h"
#include "output_zmq.h"
#include "pcap_file.h"
#include "queue.h"
#include "stats.h"
#include "task.h"

#ifdef ENABLE_DPDK
#include "dpdk/pdump.h"
#endif

static capturer_entry_t capturer_entries[] = {
    {CAPTURER_TYPE_LIBPCAP, libpcap_capture_new_from_cfg},
    {CAPTURER_TYPE_PCAP_FILE, pcap_file_capture_new_from_cfg},
#ifdef ENABLE_DPDK
    {CAPTURER_TYPE_DPDK_PDUMP, dpdk_capture_new_from_cfg},
#endif
};

static output_entry_t output_entries[] = {
    {OUTPUT_TYPE_FILE, file_output_new_from_cfg},   {OUTPUT_TYPE_ROTATING_FILE, rotating_file_output_new_from_cfg},
    {OUTPUT_TYPE_ZMQ, zmq_output_new_from_cfg},     {OUTPUT_TYPE_GRE, gre_output_new_from_cfg},
    {OUTPUT_TYPE_VXLAN, vxlan_output_new_from_cfg}, {OUTPUT_TYPE_NULL, null_output_new_from_cfg},
};

static CapturerFactory find_capturer_factory(const char *name)
{
    for (int i = 0; i < sizeof(capturer_entries) / sizeof(capturer_entry_t); i++)
    {
        if (strcmp(capturer_entries[i].name, name) == 0)
        {
            return capturer_entries[i].factory;
        }
    }
    return NULL;
}

static OutputFactory find_output_factory(const char *name)
{
    for (int i = 0; i < sizeof(output_entries) / sizeof(output_entry_t); i++)
    {
        if (strcmp(output_entries[i].name, name) == 0)
        {
            return output_entries[i].factory;
        }
    }
    return NULL;
}

capture_task_t *capture_task_new(TaskConfig *task_cfg, char *errbuf)
{
    capture_task_t *task = (capture_task_t *)calloc(1, sizeof(capture_task_t));
    if (!task)
    {
        error_format(errbuf, "failed to allocate memory for capture_task_t");
        return NULL;
    }

    CapturerFactory factory = find_capturer_factory(task_cfg->capturer.type);
    if (!factory)
    {
        error_format(errbuf, "unsupport capturer type %s", task_cfg->capturer.type);
        goto error;
    }
    task->capturer = factory(task_cfg, errbuf);
    if (!task->capturer)
        goto error;

    task->outputs = (output_base_t **)calloc(task_cfg->num_outputs, sizeof(output_base_t *));
    for (int i = 0; i < task_cfg->num_outputs; ++i)
    {
        OutputConfig *output_cfg = task_cfg->outputs[i];
        OutputFactory factory = find_output_factory(output_cfg->type);
        if (!factory)
        {
            error_format(errbuf, "unsupport output type: %s", output_cfg->type);
            goto error;
        }

        output_base_t *output = factory(task_cfg, output_cfg, errbuf);
        if (!output)
            goto error;

        task->outputs[task->num_outputs++] = output;
    }
    return task;

error:
    if (task->capturer)
        destory_capturer(task->capturer);
    for (int i = 0; i < task->num_outputs; ++i)
        destory_output(task->outputs[i]);
    free(task);
    return NULL;
}

void capture_task_destory(capture_task_t *task)
{
    if (!task)
        return;

    destory_capturer(task->capturer);
    for (int i = 0; i < task->num_outputs; ++i)
        destory_output(task->outputs[i]);
    free(task);
}

void task_handle_packet_cb(const struct pcap_pkthdr *header, const uint8_t *pkt_data, int direct, void *user)
{
    if (header->caplen < sizeof(struct ether_header))
        return;

    capture_task_t *task = (capture_task_t *)user;

    for (int i = 0; i < task->num_outputs; ++i)
    {
        output_send_packet(task->outputs[i], header, pkt_data, direct);
    }
}

void task_heartbeat_cb(void *user)
{
    capture_task_t *task = (capture_task_t *)user;
    time_t now = time(NULL);
    for (int i = 0; i < task->num_outputs; ++i)
    {
        output_heartbeat(task->outputs[i], now);
    }
}

uint64_t capture_task_poll_packets(capture_task_t *task)
{
    return capture_packets(task->capturer, task_handle_packet_cb, task_heartbeat_cb, task);
}

#define STAT_MAX_OUTPUT_PER_TASK 5
#define STAT_MAX_TASKS 1024

typedef struct TaskStats
{
    int index;
    capture_stats_t capture;
    output_stats_t outputs[STAT_MAX_OUTPUT_PER_TASK];
    int num_outputs;
} task_stats_t;

typedef struct TaskManagerStatsDetail
{
    struct timespec tm;
    task_stats_t tasks[STAT_MAX_TASKS];
    int num_tasks;
} task_manager_stats_detail_t;

typedef struct TaskManagerStatsSummary
{
    struct timespec tm;

    capture_stats_t capture;
    output_stats_t output;
} task_manager_stats_summary_t;

typedef struct Task
{
    int index;
    capture_task_t *task;
    TAILQ_ENTRY(Task) next;
} task_t;

typedef struct TaskManager
{
    TasksAllConfig *config;
    TAILQ_HEAD(, Task) tasks;

    pthread_mutex_t stats_lock;
    task_manager_stats_summary_t stats_summary;
    task_manager_stats_detail_t stats_detail;
} task_manager_t;

static task_manager_t task_mgr;

static int task_manager_new(task_manager_t *this, TasksAllConfig *config)
{
    this->config = config;
    TAILQ_INIT(&this->tasks);

    pthread_mutex_init(&this->stats_lock, NULL);

    int num_tasks = config->num_tasks;
    log_info("find %d tasks", num_tasks);

    int ret;
    char errbuf[ERROR_BUFFER_SIZE];
    for (int i = 0; i < num_tasks; ++i)
    {
        capture_task_t *cap_task = capture_task_new(config->tasks[i], errbuf);
        if (!cap_task)
        {
            log_error("new task-%d error: %s", i, errbuf);
            continue;
        }

        struct Task *task = calloc(1, sizeof(struct Task));
        if (!task)
        {
            log_error("new task-%d error: can't allocate new task", i);
            continue;
        }

        log_info("create task-%d success", i);
        task->index = i;
        task->task = cap_task;
        TAILQ_INSERT_TAIL(&this->tasks, task, next);
        ret++;
    }
    return ret;
}

int task_manager_init(TasksAllConfig *config)
{
    // use global task_mgr
    return task_manager_new(&task_mgr, config);
}

void task_manager_destory()
{
    task_manager_t *this = &task_mgr;

    task_t *item;
    task_t *titem;
    TAILQ_FOREACH_SAFE(item, &this->tasks, next, titem)
    {
        capture_task_destory(item->task);
        free(item);
    }
    free_tasks_config(this->config);
}

uint64_t task_manager_poll_packets()
{
    uint64_t num_pkts = 0;
    task_t *item;
    TAILQ_FOREACH(item, &task_mgr.tasks, next)
    {
        // poll packets
        num_pkts += capture_task_poll_packets(item->task);
    }
    return num_pkts;
}

static void task_manager_update_stats_detail()
{
    task_manager_t *this = &task_mgr;
    task_manager_stats_detail_t stats_detail = {0};

    task_t *item;
    TAILQ_FOREACH(item, &this->tasks, next)
    {
        if (stats_detail.num_tasks >= STAT_MAX_TASKS - 1)
        {
            log_warn("task manager stats only support %d tasks", STAT_MAX_TASKS);
            break;
        }

        task_stats_t *task_stats = &stats_detail.tasks[stats_detail.num_tasks];
        task_stats->index = item->index;
        task_stats->capture = item->task->capturer->stats;
        for (int i = 0; i < item->task->num_outputs; ++i)
        {
            if (i >= STAT_MAX_OUTPUT_PER_TASK - 1)
            {
                log_warn("task manager stats only support %d output per task", STAT_MAX_OUTPUT_PER_TASK);
                break;
            }

            task_stats->outputs[task_stats->num_outputs] = item->task->outputs[i]->stats;
            task_stats->num_outputs++;
        }
        stats_detail.num_tasks++;
    }

    clock_gettime(CLOCK_MONOTONIC, &stats_detail.tm);

    pthread_mutex_lock(&this->stats_lock);
    this->stats_detail = stats_detail;
    pthread_mutex_unlock(&this->stats_lock);
}

static void task_manager_update_stats_summary()
{
    task_manager_t *this = &task_mgr;
    task_manager_stats_summary_t stats_summary;
    memset(&stats_summary, 0, sizeof(task_manager_stats_summary_t));

    task_t *item;
    TAILQ_FOREACH(item, &this->tasks, next)
    {
        bytes_stats_merge(&stats_summary.capture.cap_bytes, &item->task->capturer->stats.cap_bytes);
        packets_stats_merge(&stats_summary.capture.cap_packets, &item->task->capturer->stats.cap_packets);

        packets_stats_merge(&stats_summary.capture.drop_packets, &item->task->capturer->stats.drop_packets);
        packets_stats_merge(&stats_summary.capture.ifdrop_packets, &item->task->capturer->stats.ifdrop_packets);

        for (int i = 0; i < item->task->num_outputs; ++i)
        {
            output_stats_t *output_stats = &item->task->outputs[i]->stats;
            bytes_stats_merge(&stats_summary.output.fwd_bytes, &output_stats->fwd_bytes);
            packets_stats_merge(&stats_summary.output.fwd_packets, &output_stats->fwd_packets);

            bytes_stats_merge(&stats_summary.output.direction_drop_bytes, &output_stats->direction_drop_bytes);
            packets_stats_merge(&stats_summary.output.direction_drop_packets, &output_stats->direction_drop_packets);

            bytes_stats_merge(&stats_summary.output.error_drop_bytes, &output_stats->error_drop_bytes);
            packets_stats_merge(&stats_summary.output.error_drop_packets, &output_stats->error_drop_packets);

            bytes_stats_merge(&stats_summary.output.ratelimit_drop_bytes, &output_stats->ratelimit_drop_bytes);
            packets_stats_merge(&stats_summary.output.ratelimit_drop_packets, &output_stats->ratelimit_drop_packets);
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &stats_summary.tm);

    pthread_mutex_lock(&this->stats_lock);
    this->stats_summary = stats_summary;
    pthread_mutex_unlock(&this->stats_lock);
}

void task_manager_update_stats()
{
    task_manager_update_stats_detail();
    task_manager_update_stats_summary();
}

static int bytes_stats_json_dump(bytes_stats_t st, cJSON *obj)
{
    cJSON *bytes = cJSON_CreateNumber(st.bytes);
    if (!bytes)
        return -1;
    cJSON_AddItemToObject(obj, "bytes", bytes);

    cJSON *eib = cJSON_CreateNumber(st.eib);
    if (!eib)
        return -1;
    cJSON_AddItemToObject(obj, "eib", eib);
    return 0;
}

static int packets_stats_json_dump(packets_stats_t st, cJSON *obj)
{
    cJSON *packets = cJSON_CreateNumber(st.packets);
    if (!packets)
        return -1;
    cJSON_AddItemToObject(obj, "packets", packets);

    cJSON *peta = cJSON_CreateNumber(st.peta);
    if (!peta)
        return -1;
    cJSON_AddItemToObject(obj, "peta", peta);
    return 0;
}

static int capture_stats_json_dump(capture_stats_t *stats, cJSON *capture)
{
    cJSON *cap_bytes = cJSON_CreateObject();
    if (!cap_bytes)
        return -1;
    cJSON_AddItemToObject(capture, "cap_bytes", cap_bytes);
    if (bytes_stats_json_dump(stats->cap_bytes, cap_bytes) != 0)
        return -1;

    cJSON *cap_packets = cJSON_CreateObject();
    if (!cap_packets)
        return -1;
    cJSON_AddItemToObject(capture, "cap_packets", cap_packets);
    if (packets_stats_json_dump(stats->cap_packets, cap_packets) != 0)
        return -1;

    cJSON *drop_packets = cJSON_CreateObject();
    if (!drop_packets)
        return -1;
    cJSON_AddItemToObject(capture, "drop_packets", drop_packets);
    if (packets_stats_json_dump(stats->drop_packets, drop_packets) != 0)
        return -1;

    cJSON *ifdrop_packets = cJSON_CreateObject();
    if (!ifdrop_packets)
        return -1;
    cJSON_AddItemToObject(capture, "ifdrop_packets", ifdrop_packets);
    if (packets_stats_json_dump(stats->ifdrop_packets, ifdrop_packets) != 0)
        return -1;

    return 0;
}

static int output_stats_json_dump(output_stats_t *output_stats, cJSON *output)
{
    cJSON *fwd_bytes = cJSON_CreateObject();
    if (!fwd_bytes)
        return -1;
    cJSON_AddItemToObject(output, "fwd_bytes", fwd_bytes);
    if (bytes_stats_json_dump(output_stats->fwd_bytes, fwd_bytes) != 0)
        return -1;

    cJSON *fwd_packets = cJSON_CreateObject();
    if (!fwd_packets)
        return -1;
    cJSON_AddItemToObject(output, "fwd_packets", fwd_packets);
    if (packets_stats_json_dump(output_stats->fwd_packets, fwd_packets) != 0)
        return -1;

    cJSON *direction_drop_bytes = cJSON_CreateObject();
    if (!direction_drop_bytes)
        return -1;
    cJSON_AddItemToObject(output, "direction_drop_bytes", direction_drop_bytes);
    if (bytes_stats_json_dump(output_stats->direction_drop_bytes, direction_drop_bytes) != 0)
        return -1;

    cJSON *direction_drop_packets = cJSON_CreateObject();
    if (!direction_drop_packets)
        return -1;
    cJSON_AddItemToObject(output, "direction_drop_packets", direction_drop_packets);
    if (packets_stats_json_dump(output_stats->direction_drop_packets, direction_drop_packets) != 0)
        return -1;

    cJSON *error_drop_bytes = cJSON_CreateObject();
    if (!error_drop_bytes)
        return -1;
    cJSON_AddItemToObject(output, "error_drop_bytes", error_drop_bytes);
    if (bytes_stats_json_dump(output_stats->error_drop_bytes, error_drop_bytes) != 0)
        return -1;

    cJSON *error_drop_packets = cJSON_CreateObject();
    if (!error_drop_packets)
        return -1;
    cJSON_AddItemToObject(output, "error_drop_packets", error_drop_packets);
    if (packets_stats_json_dump(output_stats->error_drop_packets, error_drop_packets) != 0)
        return -1;

    cJSON *ratelimit_drop_bytes = cJSON_CreateObject();
    if (!ratelimit_drop_bytes)
        return -1;
    cJSON_AddItemToObject(output, "ratelimit_drop_bytes", ratelimit_drop_bytes);
    if (bytes_stats_json_dump(output_stats->ratelimit_drop_bytes, ratelimit_drop_bytes) != 0)
        return -1;

    cJSON *ratelimit_drop_packets = cJSON_CreateObject();
    if (!ratelimit_drop_packets)
        return -1;
    cJSON_AddItemToObject(output, "ratelimit_drop_packets", ratelimit_drop_packets);
    if (packets_stats_json_dump(output_stats->ratelimit_drop_packets, ratelimit_drop_packets) != 0)
        return -1;

    return 0;
}

int task_manager_collect_stats_summary_command(cJSON *cmd_msg, cJSON *server_msg, void *data)
{
    task_manager_t *this = &task_mgr;

    pthread_mutex_lock(&this->stats_lock);
    task_manager_stats_summary_t stats = this->stats_summary;
    pthread_mutex_unlock(&this->stats_lock);

    cJSON *time = cJSON_CreateObject();
    if (!time)
        goto error;
    cJSON_AddItemToObject(server_msg, "time", time);

    cJSON *tv_sec = cJSON_CreateNumber(stats.tm.tv_sec);
    if (!tv_sec)
        goto error;
    cJSON_AddItemToObject(time, "sec", tv_sec);

    cJSON *tv_nsec = cJSON_CreateNumber(stats.tm.tv_nsec);
    if (!tv_nsec)
        goto error;
    cJSON_AddItemToObject(time, "nsec", tv_nsec);

    cJSON *capture = cJSON_CreateObject();
    if (!capture)
        goto error;
    cJSON_AddItemToObject(server_msg, "capture", capture);
    if (capture_stats_json_dump(&stats.capture, capture) != 0)
        goto error;

    cJSON *output = cJSON_CreateObject();
    if (!output)
        goto error;
    cJSON_AddItemToObject(server_msg, "output", output);
    if (output_stats_json_dump(&stats.output, output) != 0)
        goto error;

    return 0;
error:
    return -1;
}

int task_manager_collect_stats_detail_command(cJSON *cmd_msg, cJSON *server_msg, void *data)
{
    task_manager_t *this = &task_mgr;

    pthread_mutex_lock(&this->stats_lock);
    task_manager_stats_detail_t stats = this->stats_detail;
    pthread_mutex_unlock(&this->stats_lock);

    cJSON *time = cJSON_CreateObject();
    if (!time)
        goto error;
    cJSON_AddItemToObject(server_msg, "time", time);

    cJSON *tv_sec = cJSON_CreateNumber(stats.tm.tv_sec);
    if (!tv_sec)
        goto error;
    cJSON_AddItemToObject(time, "sec", tv_sec);

    cJSON *tv_nsec = cJSON_CreateNumber(stats.tm.tv_nsec);
    if (!tv_nsec)
        goto error;
    cJSON_AddItemToObject(time, "nsec", tv_nsec);

    cJSON *tasks = cJSON_CreateArray();
    if (!tasks)
        goto error;
    cJSON_AddItemToObject(server_msg, "tasks", tasks);

    for (int i = 0; i < stats.num_tasks; ++i)
    {
        cJSON *task = cJSON_CreateObject();
        if (!task)
            goto error;
        cJSON_AddItemToArray(tasks, task);

        cJSON *index = cJSON_CreateNumber(stats.tasks[i].index);
        if (!index)
            goto error;
        cJSON_AddItemToObject(task, "index", index);

        cJSON *capture = cJSON_CreateObject();
        if (!capture)
            goto error;
        cJSON_AddItemToObject(task, "capture", capture);

        if (capture_stats_json_dump(&stats.tasks[i].capture, capture) != 0)
            goto error;

        cJSON *outputs = cJSON_CreateArray();
        if (!outputs)
            goto error;
        cJSON_AddItemToObject(task, "outputs", outputs);

        for (int j = 0; j < stats.tasks[i].num_outputs; ++j)
        {
            output_stats_t *output_stats = &stats.tasks[i].outputs[j];

            cJSON *output = cJSON_CreateObject();
            if (!output)
                goto error;
            cJSON_AddItemToArray(outputs, output);

            if (output_stats_json_dump(output_stats, output) != 0)
                goto error;
        }
    }

    return 0;
error:
    return -1;
}