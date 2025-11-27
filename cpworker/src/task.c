#include <net/ethernet.h>
#include <pthread.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "affinity.h"
#include "atomic_util.h"
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
#include "ring_buffer.h"
#include "stats.h"
#include "task.h"
#include "thread_util.h"

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

typedef struct Task
{
    int index;
    char *fingerprint;
    capture_task_t *task;
    TAILQ_ENTRY(Task) next;
} task_t;

typedef struct TaskError
{
    int index;
    char *fingerprint;
    char errbuf[ERROR_BUFFER_SIZE];
    TAILQ_ENTRY(TaskError) next;
} task_error_t;

TAILQ_HEAD(TaskList, Task);
TAILQ_HEAD(TaskErrorList, TaskError);

static void free_task(task_t *task)
{
    if (!task)
        return;

    if (task->fingerprint)
        free(task->fingerprint);
    free(task);
}

static void free_task_error(task_error_t *task_error)
{
    if (!task_error)
        return;

    if (task_error->fingerprint)
        free(task_error->fingerprint);
    free(task_error);
}

/* Allocate a task wrapper node. fingerprint may be NULL (initial config allows it).
 * Does not take ownership of cap_task. Returns NULL on allocation failure. */
static task_t *task_wrapper_new(int index, const char *fingerprint, capture_task_t *cap_task)
{
    task_t *t = calloc(1, sizeof(task_t));
    if (!t)
    {
        log_error("allocate memory failed");
        return NULL;
    }
    if (fingerprint)
    {
        t->fingerprint = strdup(fingerprint);
        if (!t->fingerprint)
        {
            log_error("strdup task fingerprint failed");
            free(t);
            return NULL;
        }
    }
    t->index = index;
    t->task = cap_task;
    return t;
}

/* Allocate a failed-task record. Returns NULL on allocation failure. */
static task_error_t *task_error_new(int index, const char *fingerprint, const char *errbuf)
{
    task_error_t *e = calloc(1, sizeof(task_error_t));
    if (!e)
    {
        log_error("allocate memory failed");
        return NULL;
    }
    if (fingerprint)
    {
        e->fingerprint = strdup(fingerprint);
        if (!e->fingerprint)
        {
            log_error("strdup error fingerprint failed");
            free_task_error(e);
            return NULL;
        }
    }
    e->index = index;
    strncpy(e->errbuf, errbuf, ERROR_BUFFER_SIZE);
    return e;
}

typedef struct TaskStatsSummarySnapshot
{
    struct timespec tm;
    capture_stats_t capture;
    output_stats_t output;
    pipeline_buffer_stats_t pipeline_buffer;
} task_stats_summary_snapshot_t;

typedef struct TaskManager
{
    int execution_model;
    spsc_ring_t *ring;
    simple_allocator_t *alloc;

    Config *config;
    struct TaskList *tasks;
    struct TaskErrorList *errors;

    pthread_mutex_t stats_lock;
    task_stats_summary_t stats_summary;
    task_stats_summary_snapshot_t stats_summary_snapshot;
} task_manager_t;

static task_manager_t task_mgr;

capture_task_t *capture_task_new(TasksAllConfig *tasks_cfg, TaskConfig *task_cfg, task_stats_summary_t *stats,
                                 char *errbuf)
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
    task->capturer = factory(tasks_cfg, task_cfg, &stats->capture, errbuf);
    if (!task->capturer)
        goto error;

    task->outputs = (output_base_t **)calloc(task_cfg->num_outputs, sizeof(output_base_t *));
    if (!task->outputs && task_cfg->num_outputs > 0)
    {
        error_format(errbuf, "failed to allocate memory for outputs");
        goto error;
    }

    for (int i = 0; i < task_cfg->num_outputs; ++i)
    {
        OutputConfig *output_cfg = task_cfg->outputs[i];
        OutputFactory factory = find_output_factory(output_cfg->type);
        if (!factory)
        {
            error_format(errbuf, "unsupport output type: %s", output_cfg->type);
            goto error;
        }

        output_base_t *output = factory(task_cfg, output_cfg, &stats->output, errbuf);
        if (!output)
            goto error;

        task->outputs[task->num_outputs++] = output;
    }
    return task;

error:
    capture_task_destroy(task);
    return NULL;
}

void capture_task_destroy(capture_task_t *task)
{
    if (!task)
        return;

    if (task->capturer)
        destroy_capturer(task->capturer);
    for (int i = 0; i < task->num_outputs; ++i)
        destroy_output(task->outputs[i]);
    if (task->outputs)
        free(task->outputs);
    free(task);
}

static void rtc_capture_task_packet_cb(const struct pcap_pkthdr *header, const uint8_t *pkt_data, int direct,
                                       void *user)
{
    if (header->caplen < sizeof(struct ether_header))
        return;

    capture_task_t *task = (capture_task_t *)user;

    for (int i = 0; i < task->num_outputs; ++i)
    {
        output_send_packet(task->outputs[i], header, pkt_data, direct);
    }
}

static void rtc_capture_task_heartbeat_cb(void *user)
{
    capture_task_t *task = (capture_task_t *)user;
    time_t now = time(NULL);
    for (int i = 0; i < task->num_outputs; ++i)
    {
        output_heartbeat(task->outputs[i], now);
    }
}

static inline uint64_t rtc_capture_task_packets(capture_task_t *task)
{
    return capture_packets(task->capturer, rtc_capture_task_packet_cb, rtc_capture_task_heartbeat_cb, task);
}

static void pipeline_capture_task_packet_cb(const struct pcap_pkthdr *header, const uint8_t *pkt_data, int direct,
                                            void *user)
{
    if (header->caplen < sizeof(struct ether_header))
        return;

    capture_task_t *task = (capture_task_t *)user;
    while (1)
    {
        ring_msg_t *msg = simple_alloc_packet(task_mgr.alloc, header, pkt_data);
        if (msg)
        {
            msg->user = task;
            msg->pkt.direction = direct;
            while (!spsc_ring_push(task_mgr.ring, msg))
                sched_yield();
            break;
        }
        sched_yield();
    }
}

static void pipeline_capture_task_heartbeat_cb(void *user)
{
    capture_task_t *task = (capture_task_t *)user;
    time_t now = time(NULL);
    while (1)
    {
        ring_msg_t *msg = simple_alloc_heartbeat(task_mgr.alloc, now);
        if (msg)
        {
            msg->user = task;
            while (!spsc_ring_push(task_mgr.ring, msg))
                sched_yield();
            break;
        }
        sched_yield();
    }
}

static inline uint64_t pipeline_capture_task_packets(capture_task_t *task)
{
    return capture_packets(task->capturer, pipeline_capture_task_packet_cb, pipeline_capture_task_heartbeat_cb, task);
}

static int task_manager_new(task_manager_t *this, Config *config)
{
    this->execution_model = config->execution_model;
    if (this->execution_model == EXECUTION_MODEL_PIPELINE)
    {
        this->ring = spsc_ring_create(1024 * 1024);
        if (!this->ring)
        {
            log_fatal("create spsc_ring_t failed");
            return -1;
        }

        this->alloc = simple_allocator_create(config->pipeline.buffer_size_mb * 1024 * 1024);
        if (!this->alloc)
        {
            log_fatal("create simple_allocator_t failed");
            spsc_ring_destroy(this->ring);
            return -1;
        }
    }
    else
    {
        this->ring = NULL;
        this->alloc = NULL;
    }

    this->tasks = malloc(sizeof(struct TaskList));
    if (!this->tasks)
    {
        log_fatal("malloc failed");
        if (this->ring)
            spsc_ring_destroy(this->ring);
        if (this->alloc)
            simple_allocator_destroy(this->alloc);
        return -1;
    }
    this->errors = malloc(sizeof(struct TaskErrorList));
    if (!this->errors)
    {
        free(this->tasks);
        if (this->ring)
            spsc_ring_destroy(this->ring);
        if (this->alloc)
            simple_allocator_destroy(this->alloc);
        log_fatal("malloc failed");
        return -1;
    }

    this->config = config;
    TAILQ_INIT(this->tasks);
    TAILQ_INIT(this->errors);

    pthread_mutex_init(&this->stats_lock, NULL);

    int num_tasks = config->tasks_cfg->num_tasks;
    log_info("find %d tasks", num_tasks);

    int inited_count = 0;
    TaskConfig *task_config;
    char errbuf[ERROR_BUFFER_SIZE];
    for (int i = 0; i < num_tasks; ++i)
    {
        task_config = config->tasks_cfg->tasks[i];
        capture_task_t *cap_task = capture_task_new(config->tasks_cfg, task_config, &this->stats_summary, errbuf);
        if (!cap_task)
        {
            log_error("new task-%d error: %s", i, errbuf);

            task_error_t *error = task_error_new(i, task_config->fingerprint, errbuf);
            if (!error)
            {
                task_manager_destroy();
                return -1;
            }
            TAILQ_INSERT_TAIL(this->errors, error, next);
            continue;
        }

        task_t *task = task_wrapper_new(i, task_config->fingerprint, cap_task);
        if (!task)
        {
            capture_task_destroy(cap_task);
            task_manager_destroy();
            return -1;
        }
        log_info("create task-%d success", i);
        TAILQ_INSERT_TAIL(this->tasks, task, next);
        ++inited_count;
    }
    return inited_count;
}

int task_manager_init(Config *config)
{
    // use global task_mgr
    return task_manager_new(&task_mgr, config);
}

void task_manager_destroy()
{
    task_manager_t *this = &task_mgr;

    task_t *item;
    task_t *titem;
    TAILQ_FOREACH_SAFE(item, this->tasks, next, titem)
    {
        capture_task_destroy(item->task);
        TAILQ_REMOVE(this->tasks, item, next);
        free_task(item);
    }

    task_error_t *err_item;
    task_error_t *err_titem;
    TAILQ_FOREACH_SAFE(err_item, this->errors, next, err_titem)
    {
        TAILQ_REMOVE(this->errors, err_item, next);
        free_task_error(err_item);
    }

    free_config(this->config);
    free(this->tasks);
    free(this->errors);
    if (this->ring)
        spsc_ring_destroy(this->ring);
    if (this->alloc)
        simple_allocator_destroy(this->alloc);
}

void task_manager_print_errors()
{
    task_error_t *item;
    TAILQ_FOREACH(item, task_mgr.errors, next)
    {
        if (item->fingerprint != NULL)
            log_error("new task(%s) error: %s", item->fingerprint, item->errbuf);
        else
            log_error("new task(%d) error: %s", item->index, item->errbuf);
    }
}

uint64_t task_manager_poll_packets()
{
    uint64_t num_pkts = 0;
    if (task_mgr.execution_model == EXECUTION_MODEL_PIPELINE)
    {
        task_t *item;
        TAILQ_FOREACH(item, task_mgr.tasks, next)
        {
            // poll packets
            num_pkts += pipeline_capture_task_packets(item->task);
        }
    }
    else
    {
        task_t *item;
        TAILQ_FOREACH(item, task_mgr.tasks, next)
        {
            // poll packets
            num_pkts += rtc_capture_task_packets(item->task);
        }
    }
    return num_pkts;
}

typedef struct
{
    spsc_ring_t *ring;
    simple_allocator_t *alloc;
    const char *cpu_affinity;
} output_thread_arg_t;

static pthread_t output_thread;
static bool output_thread_running = false;
static bool output_drain_ring_request = false;
static bool output_drain_ring_response = false;

static inline void output_send_pkt_msg(capture_task_t *task, ring_msg_t *msg)
{
    switch (msg->type)
    {
    case RING_MSG_PACKET:
        for (int i = 0; i < task->num_outputs; ++i)
        {
            output_send_packet(task->outputs[i], &msg->pkt.hdr, msg->pkt.data, msg->pkt.direction);
        }
        break;
    case RING_MSG_HEARTBEAT:
        for (int i = 0; i < task->num_outputs; ++i)
        {
            output_heartbeat(task->outputs[i], msg->heartbeat.ts);
        }
        break;
    default:
        break;
    }
}

static void task_manager_output_drain_ring(spsc_ring_t *ring, simple_allocator_t *alloc)
{
    ring_msg_t *msg;
    size_t used = spsc_ring_used(ring);
    for (size_t i = 0; i < used; ++i)
    {
        if (spsc_ring_pop(ring, &msg))
        {
            capture_task_t *task = (capture_task_t *)(msg->user);
            output_send_pkt_msg(task, msg);
            simple_msg_free(alloc, msg);
        }
        else
        {
            break;
        }
    }
}

static void *task_manager_output_loop(void *arg)
{
    set_thread_name("taskmgr_output");

    output_thread_arg_t *thread_arg = (output_thread_arg_t *)arg;
    spsc_ring_t *ring = thread_arg->ring;
    simple_allocator_t *alloc = thread_arg->alloc;

    const char *cpu_affinity = thread_arg->cpu_affinity;
    if (cpu_affinity && strcmp(cpu_affinity, "") != 0)
    {
        if (set_cpu_affinity(cpu_affinity) != 0)
        {
            log_error("set cpu affinity to '%s' fail", cpu_affinity);
        }
    }
    free(thread_arg);

    atomic_store_release(&output_thread_running, true);

    ring_msg_t *msg;
    while (atomic_load_acquire(&output_thread_running))
    {
        if (atomic_load_acquire(&output_drain_ring_request))
        {
            task_manager_output_drain_ring(ring, alloc);
            atomic_store_release(&output_drain_ring_request, false);
            atomic_store_release(&output_drain_ring_response, true);
        }
        if (spsc_ring_pop(ring, &msg))
        {
            capture_task_t *task = (capture_task_t *)(msg->user);
            output_send_pkt_msg(task, msg);
            simple_msg_free(alloc, msg);
        }
        else
        {
            usleep(10);
        }
    }
    task_manager_output_drain_ring(ring, alloc);
}

int task_manager_start_output_thread(const char *cpu_affinity)
{
    output_thread_arg_t *arg = malloc(sizeof(output_thread_arg_t));
    if (!arg)
    {
        log_fatal("malloc failed");
        return -1;
    }
    arg->ring = task_mgr.ring;
    arg->alloc = task_mgr.alloc;
    arg->cpu_affinity = cpu_affinity;
    if (atomic_load_acquire(&output_thread_running))
    {
        log_fatal("output thread already running");
        free(arg);
        return -1;
    }
    if (pthread_create(&output_thread, NULL, task_manager_output_loop, (void *)arg) != 0)
    {
        log_fatal("failed to create output thread");
        free(arg);
        return -1;
    }
    log_info("output thread started");
    return 0;
}

void task_manager_stop_output_thread()
{
    if (!atomic_load_acquire(&output_thread_running))
        return;

    atomic_store_release(&output_thread_running, false);
    pthread_join(output_thread, NULL);
}

int task_manager_start(const char *cpu_affinity)
{
    task_manager_t *this = &task_mgr;
    if (this->execution_model == EXECUTION_MODEL_PIPELINE)
    {
        if (task_manager_start_output_thread(cpu_affinity) != 0)
        {
            log_fatal("start output thread failed");
            return -1;
        }
    }
    return 0;
}

void task_manager_stop()
{
    task_manager_t *this = &task_mgr;
    if (this->execution_model == EXECUTION_MODEL_PIPELINE)
    {
        task_manager_stop_output_thread();
    }
}

static void task_manager_update_stats_summary()
{
    task_manager_t *this = &task_mgr;
    task_stats_summary_snapshot_t stats;
    memset(&stats, 0, sizeof(task_stats_summary_snapshot_t));

    clock_gettime(CLOCK_MONOTONIC, &stats.tm);
    stats.capture = this->stats_summary.capture;
    stats.output = this->stats_summary.output;
    if (this->execution_model == EXECUTION_MODEL_PIPELINE)
    {
        stats.pipeline_buffer.ring_total = spsc_ring_size(this->ring);
        stats.pipeline_buffer.ring_used = spsc_ring_used(this->ring);

        stats.pipeline_buffer.mem_total = simple_allocator_capacity(this->alloc);
        stats.pipeline_buffer.mem_used = simple_allocator_used(this->alloc);
    }

    pthread_mutex_lock(&this->stats_lock);
    this->stats_summary_snapshot = stats;
    pthread_mutex_unlock(&this->stats_lock);
}

void task_manager_update_stats() { task_manager_update_stats_summary(); }

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

static int pipeline_buffer_stats_json_dump(pipeline_buffer_stats_t *stats, cJSON *obj)
{
    cJSON *mem_total = cJSON_CreateNumber(stats->mem_total);
    if (!mem_total)
        return -1;
    cJSON_AddItemToObject(obj, "mem_total", mem_total);

    cJSON *mem_used = cJSON_CreateNumber(stats->mem_used);
    if (!mem_used)
        return -1;
    cJSON_AddItemToObject(obj, "mem_used", mem_used);

    cJSON *ring_total = cJSON_CreateNumber(stats->ring_total);
    if (!ring_total)
        return -1;
    cJSON_AddItemToObject(obj, "ring_total", ring_total);

    cJSON *ring_used = cJSON_CreateNumber(stats->ring_used);
    if (!ring_used)
        return -1;
    cJSON_AddItemToObject(obj, "ring_used", ring_used);

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

    cJSON *heartbeat_packets = cJSON_CreateObject();
    if (!heartbeat_packets)
        return -1;
    cJSON_AddItemToObject(output, "heartbeat_packets", heartbeat_packets);
    if (packets_stats_json_dump(output_stats->heartbeat_packets, heartbeat_packets) != 0)
        return -1;

    return 0;
}

int task_manager_collect_stats_summary_command(cJSON *cmd_msg, cJSON *server_msg, void *data)
{
    task_manager_t *this = &task_mgr;

    pthread_mutex_lock(&this->stats_lock);
    task_stats_summary_snapshot_t stats = this->stats_summary_snapshot;
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

    cJSON *pipeline_buffer = cJSON_CreateObject();
    if (!pipeline_buffer)
        goto error;
    cJSON_AddItemToObject(server_msg, "pipeline_buffer", pipeline_buffer);
    if (pipeline_buffer_stats_json_dump(&stats.pipeline_buffer, pipeline_buffer) != 0)
        goto error;

    return 0;
error:
    return -1;
}

/*
 * 硬约束：
 *   - reload 期间按任务粒度切换
 *   - replace 任务必须 old 先停、new 后起
 *   - reuse 任务继续抓
 *   - 不允许重复包
 *   - 允许可预测丢包
 */

/*
 * Reload Protocol
 * ===============
 *
 * Two threads communicate via per-role mailboxes (main_mbox, reload_mbox).
 * Each thread checks its own mailbox, processes the message based on
 * the current phase, then writes a response to the other thread's mailbox.
 *
 * Message naming: REQ_* are main → reload requests; RPT_* are reload → main reports.
 * Phase naming: each phase names the state main is waiting in (what it awaits next).
 *
 * Phase transitions (driven by main thread):
 *
 *   IDLE ─signal─► AWAITING_SURVIVORS ─survivors─► AWAITING_NEW_TASKS ─new_tasks─► AWAITING_RECLAIM ─reclaimed─► IDLE
 *                          │                              │                              │
 *                          └──error──► IDLE               └──error──► IDLE               └──error──► IDLE
 *
 * Sequence:
 *
 *   Main Thread                              Reload Thread
 *   ──────────                               ─────────────
 *   reload_signal fires
 *   write REQ_PLAN to reload_mbox
 *   phase = AWAITING_SURVIVORS
 *                                            read REQ_PLAN from reload_mbox
 *                                            parse config, collect surviving tasks
 *                                            write RPT_SURVIVORS to main_mbox
 *                                            (or RPT_ERROR on failure)
 *
 *   read RPT_SURVIVORS from main_mbox
 *   swap task list to surviving subset
 *   write REQ_BUILD to reload_mbox
 *   phase = AWAITING_NEW_TASKS
 *                                            read REQ_BUILD from reload_mbox
 *                                            build full new task set
 *                                            write RPT_NEW_TASKS to main_mbox
 *                                            (or RPT_ERROR on failure)
 *
 *   read RPT_NEW_TASKS from main_mbox
 *   commit new config/tasks/errors
 *   write REQ_RECLAIM to reload_mbox
 *   phase = AWAITING_RECLAIM
 *                                            read REQ_RECLAIM from reload_mbox
 *                                            drain pipeline ring (if needed)
 *                                            reclaim old tasks/config
 *                                            write RPT_RECLAIMED to main_mbox
 *
 *   read RPT_RECLAIMED from main_mbox
 *   phase = IDLE
 *
 * Contract:
 * - Receiving RPT_SURVIVORS is the only point where task_mgr.tasks switches to the
 *   surviving subset. Replaced/removed old tasks stop being polled by
 *   task_manager_poll_packets() here.
 * - Receiving RPT_NEW_TASKS is the only point where the new full task set becomes live.
 *   New tasks do not enter task_mgr.tasks before this point.
 * - Surviving task wrappers own only their wrapper node and fingerprint string.
 *   They do not own capture_task_t.
 * - Old capture_task_t instances are reclaimed only when their fingerprint is not
 *   present in the new full task set.
 */

typedef enum
{
    RELOAD_REQ_PLAN,      /* main → reload: parse config, collect surviving tasks */
    RELOAD_RPT_SURVIVORS, /* reload → main: surviving task subset ready */
    RELOAD_REQ_BUILD,     /* main → reload: survivors applied, build full task set */
    RELOAD_RPT_NEW_TASKS, /* reload → main: new config + full task set ready */
    RELOAD_REQ_RECLAIM,   /* main → reload: new set live, reclaim old resources */
    RELOAD_RPT_RECLAIMED, /* reload → main: reclaim complete */
    RELOAD_RPT_ERROR,     /* either → either: operation failed */
} reload_msg_type_t;

typedef enum
{
    RELOAD_PHASE_IDLE,               /* no reload in progress */
    RELOAD_PHASE_AWAITING_SURVIVORS, /* REQ_PLAN sent, waiting for RPT_SURVIVORS */
    RELOAD_PHASE_AWAITING_NEW_TASKS, /* REQ_BUILD sent, waiting for RPT_NEW_TASKS */
    RELOAD_PHASE_AWAITING_RECLAIM,   /* REQ_RECLAIM sent, waiting for RPT_RECLAIMED */
} reload_phase_t;

typedef struct
{
    reload_msg_type_t type;
    union
    {
        /* RELOAD_REQ_PLAN: main → reload */
        struct
        {
            struct TaskList *current_tasks;
            task_stats_summary_t *current_stats_summary;
        } plan;

        /* RELOAD_RPT_SURVIVORS: reload → main */
        struct
        {
            struct TaskList *survivor_tasks;
        } survivors;

        /* RELOAD_REQ_BUILD: main → reload */
        struct
        {
            struct TaskList *old_tasks;
        } build;

        /* RELOAD_RPT_NEW_TASKS: reload → main */
        struct
        {
            Config *config;
            struct TaskList *tasks;
            struct TaskErrorList *errors;
        } new_set;

        /* RELOAD_REQ_RECLAIM: main → reload */
        struct
        {
            Config *old_config;
            struct TaskErrorList *old_errors;
            struct TaskList *new_tasks;
        } reclaim;

        /* RELOAD_RPT_ERROR: either direction */
        struct
        {
            /* restore_old_tasks is only meaningful when RPT_ERROR is sent during the
               AWAITING_NEW_TASKS phase (after the survivor subset was already installed) */
            struct TaskList *restore_old_tasks;
        } error;
    };
} reload_msg_t;

static pthread_t reload_thread;
static bool reload_thread_running = false;
static bool reload_signal = false;

/* Per-role mailboxes: each thread reads from its own mbox, writes to the other's */
static reload_msg_t *main_mbox = NULL;   /* main thread reads this */
static reload_msg_t *reload_mbox = NULL; /* reload thread reads this */

/* Phase is owned exclusively by the main thread */
static reload_phase_t reload_phase = RELOAD_PHASE_IDLE;

static inline task_t *find_task_by_fingerprint(const char *fingerprint, struct TaskList *tasks)
{
    task_t *item;
    TAILQ_FOREACH(item, tasks, next)
    {
        if (item->fingerprint != NULL && strcmp(item->fingerprint, fingerprint) == 0)
            return item;
    }
    return NULL;
}

void task_manager_reload_signal() { atomic_store_release(&reload_signal, true); }

static void reload_mbox_send(reload_msg_t *msg) { atomic_store_release(&reload_mbox, msg); }

static void main_mbox_send(reload_msg_t *msg) { atomic_store_release(&main_mbox, msg); }

static reload_msg_t *reload_mbox_recv(void) { return atomic_exchange_acq_rel(&reload_mbox, NULL); }

static reload_msg_t *main_mbox_recv(void) { return atomic_exchange_acq_rel(&main_mbox, NULL); }

/* Each thread owns exactly one pre-allocated message for sending.
 * The protocol is synchronous ping-pong, so a single message per thread
 * is sufficient — the receiver always consumes before the sender reuses. */
static reload_msg_t main_tx_msg;   /* main thread sends with this */
static reload_msg_t reload_tx_msg; /* reload thread sends with this */

static inline void reload_msg_set(reload_msg_t *msg, reload_msg_type_t type)
{
    memset(msg, 0, sizeof(*msg));
    msg->type = type;
}

static void request_build(struct TaskList *old_tasks)
{
    reload_msg_set(&main_tx_msg, RELOAD_REQ_BUILD);
    main_tx_msg.build.old_tasks = old_tasks;
    reload_mbox_send(&main_tx_msg);
}

static void request_reclaim(Config *old_config, struct TaskErrorList *old_errors, struct TaskList *new_tasks)
{
    reload_msg_set(&main_tx_msg, RELOAD_REQ_RECLAIM);
    main_tx_msg.reclaim.old_config = old_config;
    main_tx_msg.reclaim.old_errors = old_errors;
    main_tx_msg.reclaim.new_tasks = new_tasks;
    reload_mbox_send(&main_tx_msg);
}

static void report_error(struct TaskList *restore_tasks)
{
    reload_msg_set(&reload_tx_msg, RELOAD_RPT_ERROR);
    reload_tx_msg.error.restore_old_tasks = restore_tasks;
    main_mbox_send(&reload_tx_msg);
}

static void report_survivors(struct TaskList *survivor_tasks)
{
    reload_msg_set(&reload_tx_msg, RELOAD_RPT_SURVIVORS);
    reload_tx_msg.survivors.survivor_tasks = survivor_tasks;
    main_mbox_send(&reload_tx_msg);
}

static void report_new_tasks(Config *config, struct TaskList *tasks, struct TaskErrorList *errors)
{
    reload_msg_set(&reload_tx_msg, RELOAD_RPT_NEW_TASKS);
    reload_tx_msg.new_set.config = config;
    reload_tx_msg.new_set.tasks = tasks;
    reload_tx_msg.new_set.errors = errors;
    main_mbox_send(&reload_tx_msg);
}

static void report_reclaimed(void)
{
    reload_msg_set(&reload_tx_msg, RELOAD_RPT_RECLAIMED);
    main_mbox_send(&reload_tx_msg);
}

static void free_task_list_wrappers(struct TaskList *tasks);
static void destroy_task_error_list(struct TaskErrorList *errors);

/* ── Helper: validate all tasks have fingerprints ── */

static int validate_fingerprints(Config *config)
{
    for (int i = 0; i < config->tasks_cfg->num_tasks; ++i)
    {
        if (config->tasks_cfg->tasks[i]->fingerprint == NULL)
        {
            log_error("task %d missing fingerprint", i);
            return -1;
        }
    }
    return 0;
}

/* ── Helper: collect surviving tasks (old tasks whose fingerprint is in the new config) ── */

static struct TaskList *collect_surviving_tasks(Config *config, struct TaskList *current_tasks)
{
    struct TaskList *tasks = malloc(sizeof(struct TaskList));
    if (!tasks)
    {
        log_error("malloc failed");
        return NULL;
    }
    TAILQ_INIT(tasks);

    TaskConfig *task_config;
    for (int i = 0; i < config->tasks_cfg->num_tasks; ++i)
    {
        task_config = config->tasks_cfg->tasks[i];
        task_t *existing_task = find_task_by_fingerprint(task_config->fingerprint, current_tasks);
        if (existing_task)
        {
            task_t *survivor = task_wrapper_new(existing_task->index, existing_task->fingerprint, existing_task->task);
            if (!survivor)
                goto error;
            TAILQ_INSERT_TAIL(tasks, survivor, next);
        }
    }
    return tasks;

error:
    free_task_list_wrappers(tasks);
    return NULL;
}

/* ── Helper: build full task set (reuse surviving + create new) ── */

typedef struct
{
    struct TaskList *tasks;
    struct TaskErrorList *errors;
} build_task_set_result_t;

static void free_task_list_wrappers(struct TaskList *tasks)
{
    if (!tasks)
        return;

    task_t *item;
    task_t *titem;
    TAILQ_FOREACH_SAFE(item, tasks, next, titem)
    {
        TAILQ_REMOVE(tasks, item, next);
        free_task(item);
    }
    free(tasks);
}

static void destroy_task_error_list(struct TaskErrorList *errors)
{
    if (!errors)
        return;

    task_error_t *err_item;
    task_error_t *err_titem;
    TAILQ_FOREACH_SAFE(err_item, errors, next, err_titem)
    {
        TAILQ_REMOVE(errors, err_item, next);
        free_task_error(err_item);
    }
    free(errors);
}

static int build_full_task_set(Config *config, struct TaskList *current_tasks,
                               task_stats_summary_t *current_stats_summary, build_task_set_result_t *result)
{
    struct TaskList *tasks = malloc(sizeof(struct TaskList));
    if (!tasks)
    {
        log_error("malloc failed");
        return -1;
    }
    struct TaskErrorList *errors = malloc(sizeof(struct TaskErrorList));
    if (errors == NULL)
    {
        log_error("malloc failed");
        free(tasks);
        return -1;
    }
    TAILQ_INIT(tasks);
    TAILQ_INIT(errors);

    task_t *item;
    task_t *titem;

    char errbuf[ERROR_BUFFER_SIZE];
    TaskConfig *task_config;
    for (int i = 0; i < config->tasks_cfg->num_tasks; ++i)
    {
        task_config = config->tasks_cfg->tasks[i];
        task_t *existing_task = find_task_by_fingerprint(task_config->fingerprint, current_tasks);
        if (existing_task)
        {
            // reuse existing task
            task_t *task = task_wrapper_new(i, task_config->fingerprint, existing_task->task);
            if (!task)
                goto error;
            TAILQ_INSERT_TAIL(tasks, task, next);
            log_info("existing task-%d, fingerprint=%s", i, task_config->fingerprint);
            continue;
        }

        // create new task
        capture_task_t *cap_task = capture_task_new(config->tasks_cfg, task_config, current_stats_summary, errbuf);
        if (!cap_task)
        {
            log_error("new task-%d error: %s", i, errbuf);
            task_error_t *error = task_error_new(i, task_config->fingerprint, errbuf);
            if (!error)
                goto error;
            TAILQ_INSERT_TAIL(errors, error, next);
            continue;
        }

        task_t *task = task_wrapper_new(i, task_config->fingerprint, cap_task);
        if (!task)
        {
            capture_task_destroy(cap_task);
            goto error;
        }
        log_info("create task-%d success", i);
        TAILQ_INSERT_TAIL(tasks, task, next);
    }

    result->tasks = tasks;
    result->errors = errors;
    return 0;

error:
    TAILQ_FOREACH_SAFE(item, tasks, next, titem)
    {
        if (find_task_by_fingerprint(item->fingerprint, current_tasks) == NULL)
            capture_task_destroy(item->task);
        TAILQ_REMOVE(tasks, item, next);
        free_task(item);
    }
    free(tasks);

    destroy_task_error_list(errors);

    return -1;
}

/* ── Helper: reclaim old tasks and config ── */

static void reclaim_old_resources(Config *old_config, struct TaskErrorList *old_errors, struct TaskList *old_tasks,
                                  struct TaskList *new_tasks)
{
    task_t *item;
    task_t *titem;
    TAILQ_FOREACH_SAFE(item, old_tasks, next, titem)
    {
        task_t *existing_task = NULL;
        if (item->fingerprint != NULL)
        {
            existing_task = find_task_by_fingerprint(item->fingerprint, new_tasks);
        }
        if (!existing_task)
        {
            if (item->fingerprint)
                log_info("[reload] reclaim unused task, fingerprint=%s", item->fingerprint);
            else
                log_info("[reload] reclaim unused task, index=%d", item->index);
            capture_task_destroy(item->task);
        }

        TAILQ_REMOVE(old_tasks, item, next);
        free_task(item);
    }
    free(old_tasks);

    destroy_task_error_list(old_errors);
    free_config(old_config);
}

/* ── Main thread: task_manager_reload_cycle ── */

static void restore_full_list_on_build_failure(task_manager_t *mgr, struct TaskList *restore_old_tasks)
{
    if (!restore_old_tasks)
        return;

    log_info("[main] restoring full task list after build failure");
    free_task_list_wrappers(mgr->tasks);
    mgr->tasks = restore_old_tasks;
}

static void main_handle_survivors(task_manager_t *mgr, reload_msg_t *msg)
{
    if (msg->type == RELOAD_RPT_ERROR)
    {
        log_error("[main] reload thread reported error during config parse");
        reload_phase = RELOAD_PHASE_IDLE;
        return;
    }
    if (msg->type != RELOAD_RPT_SURVIVORS)
    {
        log_error("[main] unexpected reload msg type %d while awaiting survivors", msg->type);
        reload_phase = RELOAD_PHASE_IDLE;
        return;
    }

    log_info("[main] recv SURVIVORS, swap to surviving subset");
    struct TaskList *old_tasks = mgr->tasks;
    mgr->tasks = msg->survivors.survivor_tasks;
    request_build(old_tasks);
    reload_phase = RELOAD_PHASE_AWAITING_NEW_TASKS;
}

static void main_handle_new_tasks(task_manager_t *mgr, reload_msg_t *msg)
{
    if (msg->type == RELOAD_RPT_ERROR)
    {
        log_error("[main] reload thread reported error building task set");
        restore_full_list_on_build_failure(mgr, msg->error.restore_old_tasks);
        reload_phase = RELOAD_PHASE_IDLE;
        return;
    }
    if (msg->type != RELOAD_RPT_NEW_TASKS)
    {
        log_error("[main] unexpected reload msg type %d while awaiting new tasks", msg->type);
        reload_phase = RELOAD_PHASE_IDLE;
        return;
    }

    log_info("[main] recv NEW_TASKS, commit new config and tasks");

    Config *old_config = mgr->config;
    struct TaskErrorList *old_errors = mgr->errors;
    struct TaskList *new_tasks = msg->new_set.tasks;

    free_task_list_wrappers(mgr->tasks);
    mgr->tasks = new_tasks;
    mgr->errors = msg->new_set.errors;
    mgr->config = msg->new_set.config;

    if (mgr->execution_model != mgr->config->execution_model)
    {
        log_warn("[main] execution_model changed in new config (current=%s, new=%s), ignored",
                 mgr->execution_model == EXECUTION_MODEL_PIPELINE ? "pipeline" : "rtc",
                 mgr->config->execution_model == EXECUTION_MODEL_PIPELINE ? "pipeline" : "rtc");
    }

    if (mgr->execution_model == EXECUTION_MODEL_PIPELINE && mgr->config->execution_model == EXECUTION_MODEL_PIPELINE)
    {
        size_t old_capacity = simple_allocator_capacity(mgr->alloc);
        size_t new_capacity = mgr->config->pipeline.buffer_size_mb * 1024 * 1024;
        if (new_capacity != old_capacity)
        {
            log_info("[main] update pipeline buffer_size: %d", mgr->config->pipeline.buffer_size_mb);
            simple_allocator_resize(mgr->alloc, new_capacity);
        }
    }

    request_reclaim(old_config, old_errors, new_tasks);
    reload_phase = RELOAD_PHASE_AWAITING_RECLAIM;
}

static void main_handle_reclaimed(task_manager_t *mgr, reload_msg_t *msg)
{
    (void)mgr;
    if (msg->type == RELOAD_RPT_ERROR)
    {
        log_error("[main] reload thread reported error during cleanup");
        reload_phase = RELOAD_PHASE_IDLE;
        return;
    }
    if (msg->type != RELOAD_RPT_RECLAIMED)
    {
        log_error("[main] unexpected reload msg type %d while awaiting reclaim", msg->type);
        reload_phase = RELOAD_PHASE_IDLE;
        return;
    }

    log_info("[main] reload complete");
    reload_phase = RELOAD_PHASE_IDLE;
}

static void try_start_reload(task_manager_t *mgr)
{
    if (reload_phase != RELOAD_PHASE_IDLE)
        return;

    bool reload = atomic_exchange_acq_rel(&reload_signal, false);
    if (!reload)
        return;

    log_info("[main] start reload: send PLAN request to reload thread");
    reload_msg_set(&main_tx_msg, RELOAD_REQ_PLAN);
    main_tx_msg.plan.current_tasks = mgr->tasks;
    main_tx_msg.plan.current_stats_summary = &mgr->stats_summary;
    reload_mbox_send(&main_tx_msg);
    reload_phase = RELOAD_PHASE_AWAITING_SURVIVORS;
}

int task_manager_reload_cycle()
{
    task_manager_t *this = &task_mgr;
    reload_msg_t *msg = main_mbox_recv();

    if (msg)
    {
        switch (reload_phase)
        {
        case RELOAD_PHASE_AWAITING_SURVIVORS:
            main_handle_survivors(this, msg);
            break;
        case RELOAD_PHASE_AWAITING_NEW_TASKS:
            main_handle_new_tasks(this, msg);
            break;
        case RELOAD_PHASE_AWAITING_RECLAIM:
            main_handle_reclaimed(this, msg);
            break;
        case RELOAD_PHASE_IDLE:
        default:
            log_error("[main] unexpected reload msg in IDLE phase, type=%d", msg->type);
            break;
        }
    }

    try_start_reload(this);
    return 0;
}

/* ── Reload thread ── */

typedef struct
{
    char *config_file;
    bool drain_output_ring;
} reload_thread_arg_t;

typedef struct
{
    char *config_file;
    bool drain_output_ring;

    Config *new_config;
    struct TaskList *current_tasks;
    struct TaskList *old_tasks;
    task_stats_summary_t *current_stats_summary;
} reload_runtime_ctx_t;

static void reload_ctx_init(reload_runtime_ctx_t *ctx, reload_thread_arg_t *arg)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->config_file = arg->config_file;
    ctx->drain_output_ring = arg->drain_output_ring;
}

static void reload_ctx_reset_cycle_state(reload_runtime_ctx_t *ctx)
{
    ctx->old_tasks = NULL;
    ctx->current_tasks = NULL;
    ctx->current_stats_summary = NULL;
}

static void reload_ctx_cleanup_on_exit(reload_runtime_ctx_t *ctx)
{
    if (ctx->new_config)
        free_config(ctx->new_config);
    free(ctx->config_file);
}

static bool wait_output_drain_ring_response()
{
    while (atomic_load_acquire(&reload_thread_running))
    {
        if (atomic_load_acquire(&output_drain_ring_response))
            return true;
        usleep(1000);
    }
    return false;
}

static void reload_do_plan(reload_runtime_ctx_t *ctx, reload_msg_t *msg)
{
    log_info("[reload] recv PLAN: parsing config");
    ctx->current_tasks = msg->plan.current_tasks;
    ctx->current_stats_summary = msg->plan.current_stats_summary;

    cJSONParseError err;
    Config *config = parse_config_file(ctx->config_file, &err);
    if (!config)
    {
        log_error("[reload] parse config failed: %s", err.message);
        report_error(NULL);
        reload_ctx_reset_cycle_state(ctx);
        return;
    }

    if (validate_fingerprints(config) != 0)
    {
        log_error("[reload] config validation failed");
        free_config(config);
        report_error(NULL);
        reload_ctx_reset_cycle_state(ctx);
        return;
    }

    struct TaskList *survivors = collect_surviving_tasks(config, ctx->current_tasks);
    if (!survivors)
    {
        log_error("[reload] collect surviving tasks failed");
        free_config(config);
        report_error(NULL);
        reload_ctx_reset_cycle_state(ctx);
        return;
    }

    ctx->new_config = config;
    report_survivors(survivors);
    log_info("[reload] sent SURVIVORS to main thread");
}

static void reload_do_build(reload_runtime_ctx_t *ctx, reload_msg_t *msg)
{
    log_info("[reload] recv BUILD: building task set");
    ctx->old_tasks = msg->build.old_tasks;

    build_task_set_result_t result;
    if (build_full_task_set(ctx->new_config, ctx->current_tasks, ctx->current_stats_summary, &result) != 0)
    {
        log_error("[reload] build task set failed");
        report_error(ctx->old_tasks);
        free_config(ctx->new_config);
        ctx->new_config = NULL;
        reload_ctx_reset_cycle_state(ctx);
        return;
    }

    report_new_tasks(ctx->new_config, result.tasks, result.errors);
    ctx->new_config = NULL;
    log_info("[reload] sent NEW_TASKS to main thread");
}

static void reload_do_reclaim(reload_runtime_ctx_t *ctx, reload_msg_t *msg)
{
    log_info("[reload] recv RECLAIM: freeing old resources");

    if (ctx->drain_output_ring)
    {
        log_info("[reload] drain output ring before reclaiming old tasks");
        atomic_store_release(&output_drain_ring_request, true);
        if (wait_output_drain_ring_response())
        {
            atomic_store_release(&output_drain_ring_response, false);
        }
    }

    reclaim_old_resources(msg->reclaim.old_config, msg->reclaim.old_errors, ctx->old_tasks, msg->reclaim.new_tasks);

    reload_ctx_reset_cycle_state(ctx);
    report_reclaimed();
    log_info("[reload] sent RECLAIMED to main thread");
}

static void reload_handle_error_from_main(reload_runtime_ctx_t *ctx)
{
    log_error("[reload] main thread reported error, aborting reload");
    if (ctx->new_config)
    {
        free_config(ctx->new_config);
        ctx->new_config = NULL;
    }
    reload_ctx_reset_cycle_state(ctx);
}

static void *task_manager_reload_loop(void *arg)
{
    set_thread_name("taskmgr_reload");

    reload_thread_arg_t *thread_arg = (reload_thread_arg_t *)arg;
    reload_runtime_ctx_t ctx;
    reload_ctx_init(&ctx, thread_arg);
    free(thread_arg);

    atomic_store_release(&reload_thread_running, true);

    while (atomic_load_acquire(&reload_thread_running))
    {
        reload_msg_t *msg = reload_mbox_recv();
        if (!msg)
        {
            sleep(1);
            continue;
        }

        switch (msg->type)
        {
        case RELOAD_REQ_PLAN:
            reload_do_plan(&ctx, msg);
            break;

        case RELOAD_REQ_BUILD:
            reload_do_build(&ctx, msg);
            break;

        case RELOAD_REQ_RECLAIM:
            reload_do_reclaim(&ctx, msg);
            break;

        case RELOAD_RPT_ERROR:
            /* Main thread sent us an error — currently unreachable since
             * main thread messages never fail, but kept for protocol safety. */
            reload_handle_error_from_main(&ctx);
            break;

        default:
            log_error("[reload] unexpected msg type %d", msg->type);
            break;
        }
    }

    reload_ctx_cleanup_on_exit(&ctx);
    log_info("[reload] reload thread exit");
    return NULL;
}

int task_manager_start_reload_thread(const char *config_file)
{
    reload_thread_arg_t *arg = malloc(sizeof(reload_thread_arg_t));
    if (!arg)
    {
        log_fatal("malloc failed");
        return -1;
    }
    if (atomic_load_acquire(&reload_thread_running))
    {
        log_fatal("Reload thread already running");
        free(arg);
        return -1;
    }
    arg->config_file = strdup(config_file);
    if (task_mgr.execution_model == EXECUTION_MODEL_PIPELINE)
        arg->drain_output_ring = true;
    else
        arg->drain_output_ring = false;

    if (pthread_create(&reload_thread, NULL, task_manager_reload_loop, (void *)arg) != 0)
    {
        log_fatal("Failed to create reload thread");
        free(arg->config_file);
        free(arg);
        return -1;
    }
    log_info("reload thread started");
    return 0;
}

void task_manager_stop_reload_thread()
{
    if (!atomic_load_acquire(&reload_thread_running))
        return;

    atomic_store_release(&reload_thread_running, false);
    pthread_join(reload_thread, NULL);
}

int task_manager_reload_config_command(cJSON *cmd_msg, cJSON *server_msg, void *data)
{
    log_info("recv reload config command");
    task_manager_reload_signal();
    return 0;
}