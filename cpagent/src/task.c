#include <stdlib.h>

#include "capturer.h"
#include "dpdk_pdump.h"
#include "error.h"
#include "libpcap.h"
#include "log.h"
#include "output_file.h"
#include "output_gre.h"
#include "output_vxlan.h"
#include "output_zmq.h"
#include "task.h"
#include "taskconf.h"

static capturer_entry_t capturer_entries[] = {
    {CAPTURER_TYPE_LIBPCAP, libpcap_capture_new_from_cfg},
    {CAPTURER_TYPE_DPDK_PDUMP, dpdk_capture_new_from_cfg},
};

static output_entry_t output_entries[] = {
    {OUTPUT_TYPE_FILE, file_output_new_from_cfg},
    {OUTPUT_TYPE_ZMQ, zmq_output_new_from_cfg},
    {OUTPUT_TYPE_GRE, gre_output_new_from_cfg},
    {OUTPUT_TYPE_VXLAN, vxlan_output_new_from_cfg},
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

capture_task_t *new_capture_task(TaskConfig *task_cfg, char *errbuf)
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

void free_capture_task(capture_task_t *task)
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
    capture_task_t *task = (capture_task_t *)user;

    for (int i = 0; i < task->num_outputs; ++i)
    {
        output_send_packet(task->outputs[i], header, pkt_data, direct);
    }
}

int task_poll_packets(capture_task_t *task)
{
    return task->capturer->capture(task->capturer, task_handle_packet_cb, task);
}
