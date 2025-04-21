#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cJSON/cJSON.h"

#include "taskconf.h"

#define PARSE_ERROR -1

static void free_output(OutputConfig *output)
{
    if (!output)
        return;

    if (output->type)
    {

        if (strcmp(output->type, OUTPUT_TYPE_VXLAN) == 0)
        {
            free(output->config.vxlan.host);
            free(output->config.vxlan.bind_device);
        }
        else if (strcmp(output->type, OUTPUT_TYPE_GRE) == 0)
        {
            free(output->config.gre.host);
            free(output->config.gre.bind_device);
        }
        else if (strcmp(output->type, OUTPUT_TYPE_ZMQ) == 0)
        {
            free(output->config.zmq.host);
            free(output->config.zmq.uuid);
        }
        else if (strcmp(output->type, OUTPUT_TYPE_FILE) == 0)
        {
            free(output->config.file.name);
        }
    }

    free(output->type);
    return;
}

static void req_pattern_destory(ReqPatternConfig *req_pattern)
{
    if (!req_pattern)
        return;

    if (req_pattern->type)
    {
        if (strcmp(req_pattern->type, REQ_PATTERN_TYPE_CUSTOM_STR) == 0)
        {
            free(req_pattern->custom.pattern);
        }
    }

    free(req_pattern->type);
}

static void free_task(TaskConfig *task)
{
    if (!task)
        return;

    // free capturer
    if (task->capturer.type)
    {
        if (strcmp(task->capturer.type, CAPTURER_TYPE_LIBPCAP) == 0)
        {
            free(task->capturer.config.libpcap.bpf_filter);
        }
        else if (strcmp(task->capturer.type, CAPTURER_TYPE_DPDK_PDUMP) == 0)
        {
            free(task->capturer.config.dpdk_pdump.bpf_filter);
        }
    }
    free(task->capturer.type);

    // free outputs
    for (int i = 0; i < task->num_outputs; i++)
        free_output(task->outputs[i]);
    free(task->outputs);

    // free req_pattern
    req_pattern_destory(&task->req_pattern);

    // free commons
    free(task->interface);
    free(task->netns);
    free(task);
}

void free_tasks_config(TasksAllConfig *config)
{
    if (!config)
        return;

    for (int i = 0; i < config->num_tasks; ++i)
        free_task(config->tasks[i]);

    free(config->tasks);
    free(config);
}

static int parse_capturer_config(cJSON *engine_obj, CapturerConfig *capturer, cJSONParseError *err)
{
    cJSON *type = cJSON_GetObjectItemCaseSensitive(engine_obj, "type");
    if (!cJSON_IsString(type))
    {
        cjson_set_parse_error(err, "missing or invalid capturer type");
        return PARSE_ERROR;
    }

    capturer->type = strdup(type->valuestring);
    if (!capturer->type)
    {
        cjson_set_parse_error(err, "memory allocation failed");
        return PARSE_ERROR;
    }

    if (strcmp(capturer->type, CAPTURER_TYPE_LIBPCAP) == 0)
    {
        cJSON *libpcap_obj = cJSON_GetObjectItemCaseSensitive(engine_obj, CAPTURER_TYPE_LIBPCAP);
        if (!libpcap_obj)
        {
            cjson_set_parse_error(err, "missing libpcap config");
            return PARSE_ERROR;
        }

        // BPF Filter
        cJSON *bpf_filter = cJSON_GetObjectItemCaseSensitive(libpcap_obj, "bpf");
        if (!bpf_filter)
            capturer->config.libpcap.bpf_filter = strdup("");
        else if (cJSON_IsString(bpf_filter))
        {
            capturer->config.libpcap.bpf_filter = strdup(bpf_filter->valuestring);
            if (!capturer->config.libpcap.bpf_filter)
            {
                cjson_set_parse_error(err, "Memory allocation failed");
                return PARSE_ERROR;
            }
        }
        else
        {
            cjson_set_parse_error(err, "invalid libpcap.bpf");
            return PARSE_ERROR;
        }

        // Buffer size
        cJSON *buffer_size = cJSON_GetObjectItemCaseSensitive(libpcap_obj, "buffer_size_mb");
        if (!buffer_size)
            capturer->config.libpcap.buffer_size_mb = 256;
        else if (cJSON_IsNumber(buffer_size))
            capturer->config.libpcap.buffer_size_mb = buffer_size->valueint;
        else
        {
            cjson_set_parse_error(err, "invalid libpcap.buffer_size_mb");
            return PARSE_ERROR;
        }

        // Timeout
        cJSON *timeout = cJSON_GetObjectItemCaseSensitive(libpcap_obj, "timeout_ms");
        if (!timeout)
            capturer->config.libpcap.timeout_ms = 0;
        else if (cJSON_IsNumber(timeout))
            capturer->config.libpcap.timeout_ms = timeout->valueint;
        else
        {
            cjson_set_parse_error(err, "invalid libpcap.timeout_ms");
            return PARSE_ERROR;
        }
    }
    else if (strcmp(capturer->type, CAPTURER_TYPE_DPDK_PDUMP) == 0)
    {
        cJSON *dpdk_obj = cJSON_GetObjectItemCaseSensitive(engine_obj, CAPTURER_TYPE_DPDK_PDUMP);
        if (!dpdk_obj)
        {
            cjson_set_parse_error(err, "missing dpdk_pdump config");
            return PARSE_ERROR;
        }

        // BPF Filter
        cJSON *bpf_filter = cJSON_GetObjectItemCaseSensitive(dpdk_obj, "bpf");
        if (!bpf_filter)
            capturer->config.dpdk_pdump.bpf_filter = strdup("");
        else if (cJSON_IsString(bpf_filter))
        {
            capturer->config.dpdk_pdump.bpf_filter = strdup(bpf_filter->valuestring);
            if (!capturer->config.dpdk_pdump.bpf_filter)
            {
                cjson_set_parse_error(err, "Memory allocation failed");
                return PARSE_ERROR;
            }
        }
        else
        {
            cjson_set_parse_error(err, "invalid dpdkdump.bpf");
            return PARSE_ERROR;
        }

        // Ring size
        cJSON *ring_size = cJSON_GetObjectItemCaseSensitive(dpdk_obj, "ring_size");
        if (!ring_size)
            capturer->config.dpdk_pdump.ring_size = 2048;
        else if (cJSON_IsNumber(ring_size))
            capturer->config.dpdk_pdump.ring_size = ring_size->valueint;
        else
        {
            cjson_set_parse_error(err, "invalid dpdk_pdump.ring_size");
            return PARSE_ERROR;
        }
    }
    else
    {
        cjson_set_parse_error(err, "unknown capturer type: %s", capturer->type);
        return PARSE_ERROR;
    }

    return 0;
}

static int parse_output_config(cJSON *output_obj, OutputConfig *output, cJSONParseError *err)
{
    cJSON *type = cJSON_GetObjectItemCaseSensitive(output_obj, "type");
    if (!cJSON_IsString(type))
    {
        cjson_set_parse_error(err, "missing or invalid output type");
        return PARSE_ERROR;
    }
    output->type = strdup(type->valuestring);
    if (!output->type)
    {
        cjson_set_parse_error(err, "memory allocation failed");
        return PARSE_ERROR;
    }

    cJSON *rate_limit = cJSON_GetObjectItemCaseSensitive(output_obj, "rate_limit_mbps");
    if (!rate_limit)
        output->rate_limit_mbps = 0;
    else if (cJSON_IsNumber(rate_limit))
    {
        if (rate_limit->valueint < 0)
        {
            cjson_set_parse_error(err, "invalid rate_limit_mbps");
            return PARSE_ERROR;
        }
        output->rate_limit_mbps = rate_limit->valueint;
    }
    else
    {
        cjson_set_parse_error(err, "invalid rate_limit_mbps");
        return PARSE_ERROR;
    }

    cJSON *slice = cJSON_GetObjectItemCaseSensitive(output_obj, "slice");
    if (!slice)
        output->slice = 0;
    else if (cJSON_IsNumber(slice))
        output->slice = slice->valueint;
    else
    {
        cjson_set_parse_error(err, "invalid slice");
        return PARSE_ERROR;
    }

    // Type specific config
    if (strcmp(output->type, OUTPUT_TYPE_VXLAN) == 0)
    {
        cJSON *vxlan_obj = cJSON_GetObjectItemCaseSensitive(output_obj, OUTPUT_TYPE_VXLAN);
        if (!vxlan_obj)
        {
            cjson_set_parse_error(err, "missing vxlan config");
            return PARSE_ERROR;
        }

        // host
        cJSON *host = cJSON_GetObjectItemCaseSensitive(vxlan_obj, "host");
        if (!cJSON_IsString(host))
        {
            cjson_set_parse_error(err, "missing or invalid vxlan.host");
            return PARSE_ERROR;
        }
        output->config.vxlan.host = strdup(host->valuestring);

        // Port
        cJSON *port = cJSON_GetObjectItemCaseSensitive(vxlan_obj, "port");
        if (!port)
            output->config.vxlan.port = 4789;
        else if (cJSON_IsNumber(port))
            output->config.vxlan.port = port->valueint;
        else
        {
            cjson_set_parse_error(err, "invalid vxlan.port");
            return PARSE_ERROR;
        }

        // Capture time
        cJSON *capture_time = cJSON_GetObjectItemCaseSensitive(vxlan_obj, "capture_time");
        if (!capture_time)
            output->config.vxlan.capture_time = false;
        else if (cJSON_IsBool(capture_time))
        {
            if (cJSON_IsTrue(capture_time))
                output->config.vxlan.capture_time = true;
            else
                output->config.vxlan.capture_time = false;
        }
        else
        {
            cjson_set_parse_error(err, "invalid vxlan.capture_time");
            return PARSE_ERROR;
        }

        // VNI1 and VNI2
        cJSON *vni1 = cJSON_GetObjectItemCaseSensitive(vxlan_obj, "vni1");
        cJSON *vni2 = cJSON_GetObjectItemCaseSensitive(vxlan_obj, "vni2");
        if (vni1)
        {
            if (cJSON_IsNumber(vni1))
            {
                output->config.vxlan.vni_version = 1;
                output->config.vxlan.vni = vni1->valueint;
            }
            else
            {
                cjson_set_parse_error(err, "invalid vxlan.vni1");
                return PARSE_ERROR;
            }
        }
        else if (vni2)
        {
            if (cJSON_IsNumber(vni2))
            {
                output->config.vxlan.vni_version = 2;
                output->config.vxlan.vni = vni2->valueint;
            }
            else
            {
                cjson_set_parse_error(err, "invalid vxlan.vni2");
                return PARSE_ERROR;
            }
        }
        else
        {
            cjson_set_parse_error(err, "require vxlan.vni1 or vxlan.vni2");
            return PARSE_ERROR;
        }

        // Bind device
        cJSON *bind = cJSON_GetObjectItemCaseSensitive(vxlan_obj, "bind_device");
        if (!bind)
            output->config.vxlan.bind_device = strdup("");
        else if (cJSON_IsString(bind))
            output->config.vxlan.bind_device = strdup(bind->valuestring);
        else
        {
            cjson_set_parse_error(err, "invalid vxlan.bind_device");
            return PARSE_ERROR;
        }

        // pmtudisc
        cJSON *pmtudisc = cJSON_GetObjectItemCaseSensitive(vxlan_obj, "pmtudisc");
        if (!pmtudisc)
            output->config.vxlan.pmtudisc = -1;
        else if (cJSON_IsString(pmtudisc))
        {

            if (strcmp(pmtudisc->valuestring, "do") == 0)
                output->config.vxlan.pmtudisc = IP_PMTUDISC_DO;
            else if (strcmp(pmtudisc->valuestring, "dont") == 0)
                output->config.vxlan.pmtudisc = IP_PMTUDISC_DONT;
            else if (strcmp(pmtudisc->valuestring, "want") == 0)
                output->config.vxlan.pmtudisc = IP_PMTUDISC_WANT;
            else
            {
                cjson_set_parse_error(err, "invalid vxlan.pmtudisc %s", pmtudisc->valuestring);
                return PARSE_ERROR;
            }
        }
        else
        {
            cjson_set_parse_error(err, "invalid vxlan.pmtudisc");
            return PARSE_ERROR;
        }
    }
    else if (strcmp(output->type, OUTPUT_TYPE_GRE) == 0)
    {
        cJSON *gre_obj = cJSON_GetObjectItemCaseSensitive(output_obj, OUTPUT_TYPE_GRE);
        if (!gre_obj)
        {
            cjson_set_parse_error(err, "missing gre config");
            return PARSE_ERROR;
        }

        cJSON *host = cJSON_GetObjectItemCaseSensitive(gre_obj, "host");
        if (!cJSON_IsString(host))
        {
            cjson_set_parse_error(err, "missing or invalid gre.host");
            return PARSE_ERROR;
        }
        output->config.gre.host = strdup(host->valuestring);

        // Service Tag
        cJSON *service_tag = cJSON_GetObjectItemCaseSensitive(gre_obj, "service_tag");
        if (!service_tag)
            output->config.gre.service_tag = 0xffffffff;
        else if (cJSON_IsNumber(service_tag))
            output->config.gre.service_tag = service_tag->valueint;
        else
        {
            cjson_set_parse_error(err, "invalid gre.service_tag");
            return PARSE_ERROR;
        }

        // Bind device
        cJSON *bind = cJSON_GetObjectItemCaseSensitive(gre_obj, "bind_device");
        if (!bind)
            output->config.gre.bind_device = strdup("");
        else if (cJSON_IsString(bind))
            output->config.gre.bind_device = strdup(bind->valuestring);
        else
        {
            cjson_set_parse_error(err, "invalid gre.bind_device");
            return PARSE_ERROR;
        }

        // pmtudisc
        cJSON *pmtudisc = cJSON_GetObjectItemCaseSensitive(gre_obj, "pmtudisc");
        if (!pmtudisc)
            output->config.gre.pmtudisc = -1;
        else if (cJSON_IsString(pmtudisc))
        {

            if (strcmp(pmtudisc->valuestring, "do") == 0)
                output->config.gre.pmtudisc = IP_PMTUDISC_DO;
            else if (strcmp(pmtudisc->valuestring, "dont") == 0)
                output->config.gre.pmtudisc = IP_PMTUDISC_DONT;
            else if (strcmp(pmtudisc->valuestring, "want") == 0)
                output->config.gre.pmtudisc = IP_PMTUDISC_WANT;
            else
            {
                cjson_set_parse_error(err, "invalid gre.pmtudisc %s", pmtudisc->valuestring);
                return PARSE_ERROR;
            }
        }
        else
        {
            cjson_set_parse_error(err, "invalid gre.pmtudisc");
            return PARSE_ERROR;
        }
    }
    else if (strcmp(output->type, OUTPUT_TYPE_ZMQ) == 0)
    {
        cJSON *zmq_obj = cJSON_GetObjectItemCaseSensitive(output_obj, OUTPUT_TYPE_ZMQ);
        if (!zmq_obj)
        {
            cjson_set_parse_error(err, "missing zmq config");
            return PARSE_ERROR;
        }

        // Host
        cJSON *host = cJSON_GetObjectItemCaseSensitive(zmq_obj, "host");
        if (!cJSON_IsString(host))
        {
            cjson_set_parse_error(err, "missing or invalid zmq.host");
            return PARSE_ERROR;
        }
        output->config.zmq.host = strdup(host->valuestring);

        // Port
        cJSON *port = cJSON_GetObjectItemCaseSensitive(zmq_obj, "port");
        if (!port)
        {
            cjson_set_parse_error(err, "missing zmq.port");
            return PARSE_ERROR;
        }
        else if (cJSON_IsNumber(port))
            output->config.zmq.port = port->valueint;
        else
        {
            cjson_set_parse_error(err, "invalid zmq.port");
            return PARSE_ERROR;
        }

        // High Watermark
        cJSON *hwm = cJSON_GetObjectItemCaseSensitive(zmq_obj, "hwm");
        if (!hwm)
            output->config.zmq.hwm = 100;
        else if (cJSON_IsNumber(hwm))
            output->config.zmq.hwm = hwm->valueint;
        else
        {
            cjson_set_parse_error(err, "invalid zmq.hwm");
            return PARSE_ERROR;
        }

        // Keybit
        cJSON *service_tag = cJSON_GetObjectItemCaseSensitive(zmq_obj, "service_tag");
        if (!service_tag)
            output->config.zmq.service_tag = 0xffffffff;
        else if (cJSON_IsNumber(service_tag))
            output->config.zmq.service_tag = service_tag->valueint;
        else
        {
            cjson_set_parse_error(err, "invalid zmq.service_tag");
            return PARSE_ERROR;
        }

        // uuid
        cJSON *uuid = cJSON_GetObjectItemCaseSensitive(zmq_obj, "uuid");
        if (!uuid)
            output->config.zmq.uuid = strdup("");
        else if (cJSON_IsString(uuid))
            output->config.zmq.uuid = strdup(uuid->valuestring);
        else
        {
            cjson_set_parse_error(err, "invalid zmq.uuid");
            return PARSE_ERROR;
        }
    }
    else if (strcmp(output->type, OUTPUT_TYPE_FILE) == 0)
    {
        cJSON *file_obj = cJSON_GetObjectItemCaseSensitive(output_obj, OUTPUT_TYPE_FILE);
        if (!file_obj)
        {
            cjson_set_parse_error(err, "missing file config");
            return PARSE_ERROR;
        }

        // Name
        cJSON *name = cJSON_GetObjectItemCaseSensitive(file_obj, "name");
        if (!cJSON_IsString(name))
        {
            cjson_set_parse_error(err, "missing or invalid file.name");
            return PARSE_ERROR;
        }
        output->config.file.name = strdup(name->valuestring);
    }
    else if (strcmp(output->type, OUTPUT_TYPE_ROTATING_FILE) == 0)
    {
        cJSON *rotating_file_obj = cJSON_GetObjectItemCaseSensitive(output_obj, OUTPUT_TYPE_ROTATING_FILE);
        if (!rotating_file_obj)
        {
            cjson_set_parse_error(err, "missing rotating_file config");
            return PARSE_ERROR;
        }

        cJSON *file_root = cJSON_GetObjectItemCaseSensitive(rotating_file_obj, "file_root");
        if (!cJSON_IsString(file_root))
        {
            cjson_set_parse_error(err, "missing or invalid rotating_file.file_root");
            return PARSE_ERROR;
        }
        output->config.rotating_file.file_root = strdup(file_root->valuestring);

        cJSON *max_file_interval = cJSON_GetObjectItemCaseSensitive(rotating_file_obj, "max_file_interval");
        if (!max_file_interval)
            output->config.rotating_file.max_file_interval = -1;
        else if (cJSON_IsNumber(max_file_interval))
            output->config.rotating_file.max_file_interval = max_file_interval->valueint;
        else
        {
            cjson_set_parse_error(err, "invalid rotating_file.max_file_interval");
            return PARSE_ERROR;
        }
    }
    else
    {
        cjson_set_parse_error(err, "unknown output type: %s", output->type);
        return PARSE_ERROR;
    }

    return 0;
}

static int parse_req_pattern_config(cJSON *req_pattern_obj, ReqPatternConfig *req_pattern, cJSONParseError *err)
{
    cJSON *type = cJSON_GetObjectItemCaseSensitive(req_pattern_obj, "type");
    if (!cJSON_IsString(type))
    {
        cjson_set_parse_error(err, "missing or invalid output type");
        return PARSE_ERROR;
    }
    req_pattern->type = strdup(type->valuestring);
    if (!req_pattern->type)
    {
        cjson_set_parse_error(err, "memory allocation failed");
        return PARSE_ERROR;
    }

    if (strcmp(req_pattern->type, REQ_PATTERN_TYPE_AUTO_STR) == 0)
    {
        // noops
    }
    else if (strcmp(req_pattern->type, REQ_PATTERN_TYPE_CUSTOM_STR) == 0)
    {
        cJSON *custom = cJSON_GetObjectItemCaseSensitive(req_pattern_obj, "custom");
        if (!cJSON_IsObject(custom))
        {
            cjson_set_parse_error(err, "custom %d is not an object");
            return PARSE_ERROR;
        }
        cJSON *pattern = cJSON_GetObjectItemCaseSensitive(custom, "pattern");
        if (!pattern)
        {
            req_pattern->custom.pattern = strdup("");
        }
        else if (cJSON_IsString(pattern))
        {
            req_pattern->custom.pattern = strdup(pattern->valuestring);
        }
        else
        {
            cjson_set_parse_error(err, "invalid custom.pattern");
            return PARSE_ERROR;
        }
    }
    else
    {
        cjson_set_parse_error(err, "unknown req_pattern type: %s", req_pattern->type);
        return PARSE_ERROR;
    }
    return 0;
}

static int parse_task_config(cJSON *task_obj, TaskConfig *task, cJSONParseError *err)
{
    // Parse interface
    cJSON *interface = cJSON_GetObjectItemCaseSensitive(task_obj, "interface");
    if (!cJSON_IsString(interface))
    {
        cjson_set_parse_error(err, "missing or invalid interface");
        return PARSE_ERROR;
    }
    task->interface = strdup(interface->valuestring);
    if (!task->interface)
    {
        cjson_set_parse_error(err, "memory allocation failed");
        return PARSE_ERROR;
    }

    cJSON *snaplen = cJSON_GetObjectItemCaseSensitive(task_obj, "snaplen");
    if (!snaplen)
        task->snaplen = 2048;
    else if (cJSON_IsNumber(snaplen))
        task->snaplen = snaplen->valueint;
    else
    {
        cjson_set_parse_error(err, "invalid snaplen");
        return PARSE_ERROR;
    }

    // Parse netns
    cJSON *netns = cJSON_GetObjectItemCaseSensitive(task_obj, "netns");
    if (!netns)
        task->netns = strdup("");
    else if (cJSON_IsString(netns))
    {
        task->netns = strdup(netns->valuestring);
        if (!task->netns)
        {
            cjson_set_parse_error(err, "memory allocation failed");
            return PARSE_ERROR;
        }
    }
    else
    {
        cjson_set_parse_error(err, "invalid netns");
        return PARSE_ERROR;
    }

    // Parse req_pattern
    cJSON *req_pattern = cJSON_GetObjectItemCaseSensitive(task_obj, "req_pattern");
    if (!req_pattern)
    {
        task->req_pattern.type = strdup(REQ_PATTERN_TYPE_NONE_STR);
    }
    else if (!cJSON_IsObject(req_pattern))
    {
        cjson_set_parse_error(err, "invalid netns");
        return PARSE_ERROR;
    }
    else
    {
        if (parse_req_pattern_config(req_pattern, &task->req_pattern, err) != 0)
        {
            cjson_wrap_parse_error(err, "parse req_pattern error");
            return PARSE_ERROR;
        }
    }

    // Parse capturer
    cJSON *capturer = cJSON_GetObjectItemCaseSensitive(task_obj, "capturer");
    if (!cJSON_IsObject(capturer))
    {
        cjson_set_parse_error(err, "missing or invalid capturer config");
        return PARSE_ERROR;
    }
    if (parse_capturer_config(capturer, &task->capturer, err) != 0)
    {
        cjson_wrap_parse_error(err, "parse capturer error");
        return PARSE_ERROR;
    }

    // Parse outputs
    cJSON *outputs = cJSON_GetObjectItemCaseSensitive(task_obj, "outputs");
    if (!cJSON_IsArray(outputs))
    {
        cjson_set_parse_error(err, "missing or invalid outputs config");
        return PARSE_ERROR;
    }

    int num_outputs = cJSON_GetArraySize(outputs);
    task->outputs = (OutputConfig **)calloc(num_outputs, sizeof(OutputConfig *));
    if (!task->outputs)
    {
        cjson_set_parse_error(err, "memory allocation failed");
        return PARSE_ERROR;
    }

    for (int i = 0; i < num_outputs; i++)
    {
        cJSON *output_obj = cJSON_GetArrayItem(outputs, i);
        if (!cJSON_IsObject(output_obj))
        {
            cjson_set_parse_error(err, "output %d is not an object", i);
            return PARSE_ERROR;
        }

        OutputConfig *output = (OutputConfig *)calloc(1, sizeof(OutputConfig));
        if (!output)
        {
            cjson_set_parse_error(err, "memory allocation failed");
            return PARSE_ERROR;
        }
        if (parse_output_config(output_obj, output, err) != 0)
        {
            free_output(output);
            cjson_wrap_parse_error(err, "parse output error");
            return PARSE_ERROR;
        }
        task->outputs[task->num_outputs++] = output;
    }

    return 0;
}

TasksAllConfig *parse_tasks_config(char *data, cJSONParseError *err)
{
    cJSON *json = cJSON_Parse(data);
    if (!json)
    {
        cjson_set_parse_error(err, "JSON parse error before: %s", cJSON_GetErrorPtr());
        return NULL;
    }

    TasksAllConfig *config = (TasksAllConfig *)calloc(1, sizeof(TasksAllConfig));
    if (!config)
    {
        cjson_set_parse_error(err, "memory allocation failed");
        cJSON_Delete(json);
        return NULL;
    }

    cJSON *tasks = cJSON_GetObjectItemCaseSensitive(json, "tasks");
    if (!cJSON_IsArray(tasks))
    {
        cjson_set_parse_error(err, "missing or invalid tasks array");
        goto error;
    }

    int num_tasks = cJSON_GetArraySize(tasks);
    config->tasks = (TaskConfig **)calloc(num_tasks, sizeof(TaskConfig *));
    if (!config->tasks)
    {
        cjson_set_parse_error(err, "memory allocation failed");
        goto error;
    }

    for (int i = 0; i < num_tasks; i++)
    {
        cJSON *task_obj = cJSON_GetArrayItem(tasks, i);
        if (!cJSON_IsObject(task_obj))
        {
            cjson_set_parse_error(err, "task %d is not an object", i);
            goto error;
        }

        TaskConfig *task = (TaskConfig *)calloc(1, sizeof(TaskConfig));
        if (!task)
        {
            cjson_set_parse_error(err, "memory allocation failed");
            goto error;
        }

        if (parse_task_config(task_obj, task, err) != 0)
        {
            free_task(task);
            cjson_wrap_parse_error(err, "parse task %d error", i);
            goto error;
        }
        config->tasks[config->num_tasks++] = task;
    }

    cJSON_Delete(json);
    return config;

error:
    cJSON_Delete(json);
    free_tasks_config(config);
    return NULL;
}

static char *read_file_contents(const char *filename, cJSONParseError *error)
{
    FILE *fp = fopen(filename, "rb");
    if (!fp)
    {
        cjson_set_parse_error(error, "failed to open file: %s", filename);
        return NULL;
    }

    fseek(fp, 0, SEEK_END);
    long length = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (length <= 0)
    {
        cjson_set_parse_error(error, "empty file: %s", filename);
        fclose(fp);
        return NULL;
    }

    char *buffer = (char *)malloc(length + 1);
    if (!buffer)
    {
        cjson_set_parse_error(error, "memory allocation failed for file buffer");
        fclose(fp);
        return NULL;
    }

    if (fread(buffer, 1, length, fp) != (size_t)length)
    {
        cjson_set_parse_error(error, "partial read of file: %s", filename);
        free(buffer);
        fclose(fp);
        return NULL;
    }

    buffer[length] = '\0';
    fclose(fp);
    return buffer;
}

TasksAllConfig *parse_tasks_file(const char *filename, cJSONParseError *err)
{
    char *json_str = read_file_contents(filename, err);
    if (!json_str)
        return NULL;

    TasksAllConfig *config = parse_tasks_config(json_str, err);
    free(json_str);
    return config;
}
