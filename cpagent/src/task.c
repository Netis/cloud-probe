#include <stdlib.h>

#include "capturer.h"
#include "dpdk_pdump.h"
#include "error.h"
#include "libpcap.h"
#include "log.h"
#include "output_file.h"
#include "task.h"
#include "taskconf.h"

capture_task_t *new_capture_task(TaskConfig *task_cfg, char *errbuf)
{
    capture_task_t *task = (capture_task_t *)calloc(1, sizeof(capture_task_t));
    if (!task)
    {
        snprintf(errbuf, ERROR_BUFFER_SIZE, "failed to allocate memory for capture_task_t");
        return NULL;
    }

    if (strcmp(task_cfg->capturer.type, CAPTURER_ENGINE_DPDK_PDUMP) == 0)
    {
        dpdk_pdump_options_t opts = {
            .interface = task_cfg->interface,
            .snaplen = task_cfg->snaplen,
            .promiscuous_mode = true,
            .bpf_filter = task_cfg->capturer.config.dpdk_pdump.bpf_filter,
            .pool_name = "cpagent_capture_mbufs",
            .ring_name = "cpagent_capture_ring",
            .ring_size = task_cfg->capturer.config.dpdk_pdump.ring_size,
            .num_mbufs = 2 * task_cfg->capturer.config.dpdk_pdump.ring_size,
        };
        log_info("dpdk pdump options, interface %s, snaplen %d, ring_size: %d, num_mbufs: %d, bpf_filter: `%s`",
                 opts.interface, opts.snaplen, opts.ring_size, opts.num_mbufs, opts.bpf_filter);

        task->capturer = (capturer_base_t *)new_dpdk_capturer(opts, errbuf);
        if (!task->capturer)
            goto error;
    }
    else if (strcmp(task_cfg->capturer.type, CAPTURER_ENGINE_LIBPCAP) == 0)
    {
        libpcap_options_t opts = {
            .interface = task_cfg->interface,
            .snaplen = task_cfg->snaplen,
            .promisc = 0,
            .buffer_size = task_cfg->capturer.config.libpcap.buffer_size_mb * 1024 * 1024,
            .bpf_filter = task_cfg->capturer.config.libpcap.bpf_filter,
        };
        log_info("libpcap options, interface %s, snaplen %d, buffer_size: %d, bpf_filter: `%s`", opts.interface,
                 opts.snaplen, opts.buffer_size, opts.bpf_filter);

        task->capturer = (capturer_base_t *)new_libpcap_capturer(opts, errbuf);
        if (!task->capturer)
            goto error;
    }
    else
    {
        snprintf(errbuf, ERROR_BUFFER_SIZE, "unsupport capturer type %s", task_cfg->capturer.type);
        goto error;
    }

    task->outputs = (output_base_t **)calloc(task_cfg->num_outputs, sizeof(output_base_t *));
    for (int i = 0; i < task_cfg->num_outputs; ++i)
    {
        OutputConfig *output_cfg = task_cfg->outputs[i];
        if (strcmp(output_cfg->type, OUTPUT_TYPE_FILE) == 0)
        {
            file_output_t *output = new_file_output(output_cfg->config.file.name, task_cfg->snaplen, errbuf);
            if (!output)
                goto error;

            task->outputs[task->num_outputs++] = (output_base_t *)output;
        }
        else
        {
            snprintf(errbuf, ERROR_BUFFER_SIZE, "unsupport output type: %s", output_cfg->type);
            goto error;
        }
    }
    return task;

error:
    if (task->capturer)
        task->capturer->destory(task->capturer);
    for (int i = 0; i < task->num_outputs; ++i)
        task->outputs[i]->destory(task->outputs[i]);
    free(task);
    return NULL;
}

void free_capture_task(capture_task_t *task)
{
    if (!task)
        return;

    task->capturer->destory(task->capturer);
    for (int i = 0; i < task->num_outputs; ++i)
        task->outputs[i]->destory(task->outputs[i]);
    free(task);
}

void task_handle_packet_cb(const struct pcap_pkthdr *header, const uint8_t *pkt_data, void *user_data)
{
    capture_task_t *task = (capture_task_t *)user_data;

    for (int i = 0; i < task->num_outputs; ++i)
    {
        task->outputs[i]->send_packet(task->outputs[i], header, pkt_data, PKT_DIR_INCOMING);
    }
}

int task_poll_packets(capture_task_t *task)
{
    return task->capturer->capture(task->capturer, task_handle_packet_cb, task);
}
