#include "taskconf.h"
#include "cJSON/cJSON.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void free_task(TaskConfig *task)
{
    if (!task)
        return;

    // Free engine config
    if (task->engine.type)
    {
        if (strcmp(task->engine.type, "libpcap") == 0)
        {
            free(task->engine.config.libpcap.bpf_filter);
        }
        else if (strcmp(task->engine.type, "dpdkdump") == 0)
        {
            free(task->engine.config.dpdkdump.bpf_filter);
        }
    }

    // Free output config
    if (task->output.type)
    {

        if (strcmp(task->output.type, "vxlan") == 0)
        {
            for (int i = 0; i < task->output.config.vxlan.remote_ip_count; i++)
            {
                free(task->output.config.vxlan.remote_ips[i]);
            }
            free(task->output.config.vxlan.remote_ips);
            free(task->output.config.vxlan.bind_device);
        }
        else if (strcmp(task->output.type, "gre") == 0)
        {
            for (int i = 0; i < task->output.config.gre.remote_ip_count; i++)
            {
                free(task->output.config.gre.remote_ips[i]);
            }
            free(task->output.config.gre.remote_ips);
            free(task->output.config.gre.bind_device);
        }
        else if (strcmp(task->output.type, "zmq") == 0)
        {
            for (int i = 0; i < task->output.config.zmq.remote_ip_count; i++)
            {
                free(task->output.config.zmq.remote_ips[i]);
            }
            free(task->output.config.zmq.remote_ips);
        }
    }

    free(task->engine.type);
    free(task->output.type);
    free(task->interface);
    free(task->netns);
    free(task);
}

void free_tasks_config(TaskSetConfig *config)
{
    if (!config)
        return;

    for (int i = 0; i < config->num_tasks; i++)
        free_task(config->tasks[i]);

    free(config->tasks);
    free(config);
}

static char **parse_string_array(const cJSON *arr, int *count, cJSONParseError *err)
{
    if (!cJSON_IsArray(arr))
    {
        set_cjson_parse_error(err, "expected array");
        return NULL;
    }

    *count = cJSON_GetArraySize(arr);
    if (*count == 0)
    {
        set_cjson_parse_error(err, "empty array not allowed");
        return NULL;
    }

    char **strs = (char **)malloc(*count * sizeof(char *));
    if (!strs)
    {
        set_cjson_parse_error(err, "memory allocation failed");
        return NULL;
    }

    for (int i = 0; i < *count; i++)
    {
        cJSON *item = cJSON_GetArrayItem(arr, i);
        if (!cJSON_IsString(item))
        {
            set_cjson_parse_error(err, "array element is not string");
            for (int j = 0; j < i; j++)
                free(strs[j]);
            free(strs);
            return NULL;
        }

        strs[i] = strdup(item->valuestring);
        if (!strs[i])
        {
            set_cjson_parse_error(err, "memory allocation failed");
            for (int j = 0; j < i; j++)
                free(strs[j]);
            free(strs);
            return NULL;
        }
    }
    return strs;
}

static int parse_engine_config(cJSON *engine_obj, EngineConfig *engine, cJSONParseError *err)
{
    cJSON *type = cJSON_GetObjectItemCaseSensitive(engine_obj, "type");
    if (!cJSON_IsString(type))
    {
        set_cjson_parse_error(err, "missing or invalid engine type");
        return 0;
    }

    engine->type = strdup(type->valuestring);
    if (!engine->type)
    {
        set_cjson_parse_error(err, "memory allocation failed");
        return 0;
    }

    if (strcmp(engine->type, "libpcap") == 0)
    {
        cJSON *libpcap_obj = cJSON_GetObjectItemCaseSensitive(engine_obj, "libpcap");
        if (!libpcap_obj)
        {
            set_cjson_parse_error(err, "missing libpcap config");
            return 0;
        }

        // Snapshot Length
        cJSON *snaplen = cJSON_GetObjectItemCaseSensitive(libpcap_obj, "snaplen");
        if (!snaplen)
            engine->config.libpcap.snaplen = 2048;
        else if (cJSON_IsNumber(snaplen))
            engine->config.libpcap.snaplen = snaplen->valueint;
        else
        {
            set_cjson_parse_error(err, "invalid libpcap.snaplen");
            return 0;
        }

        // BPF Filter
        cJSON *bpf_filter = cJSON_GetObjectItemCaseSensitive(libpcap_obj, "bpf_filter");
        if (!bpf_filter)
            engine->config.libpcap.bpf_filter = strdup("");
        else if (cJSON_IsString(bpf_filter))
        {
            engine->config.libpcap.bpf_filter = strdup(bpf_filter->valuestring);
            if (!engine->config.libpcap.bpf_filter)
            {
                set_cjson_parse_error(err, "Memory allocation failed");
                return 0;
            }
        }
        else
        {
            set_cjson_parse_error(err, "invalid libpcap.bpf_filter");
            return 0;
        }

        // Buffer size
        cJSON *buffer_size = cJSON_GetObjectItemCaseSensitive(libpcap_obj, "buffer_size_mb");
        if (!buffer_size)
            engine->config.libpcap.buffer_size_mb = 256;
        else if (cJSON_IsNumber(buffer_size))
            engine->config.libpcap.buffer_size_mb = buffer_size->valueint;
        else
        {
            set_cjson_parse_error(err, "invalid libpcap.buffer_size_mb");
            return 0;
        }

        // Timeout
        cJSON *timeout = cJSON_GetObjectItemCaseSensitive(libpcap_obj, "timeout_ms");
        if (!timeout)
            engine->config.libpcap.timeout_ms = 3000;
        else if (cJSON_IsNumber(timeout))
            engine->config.libpcap.timeout_ms = timeout->valueint;
        else
        {
            set_cjson_parse_error(err, "invalid libpcap.timeout_ms");
            return 0;
        }
    }
    else if (strcmp(engine->type, "dpdkdump") == 0)
    {
        cJSON *dpdk_obj = cJSON_GetObjectItemCaseSensitive(engine_obj, "dpdkdump");
        if (!dpdk_obj)
        {
            set_cjson_parse_error(err, "missing dpdkdump config");
            return 0;
        }

        // Snaplen
        cJSON *snaplen = cJSON_GetObjectItemCaseSensitive(dpdk_obj, "snaplen");
        if (!snaplen)
            engine->config.dpdkdump.snaplen = 2048;
        else if (cJSON_IsNumber(snaplen))
            engine->config.dpdkdump.snaplen = snaplen->valueint;
        else
        {
            set_cjson_parse_error(err, "invalid dpdkdump.snaplen");
            return 0;
        }

        // BPF Filter
        cJSON *bpf_filter = cJSON_GetObjectItemCaseSensitive(dpdk_obj, "bpf_filter");
        if (!bpf_filter)
            engine->config.dpdkdump.bpf_filter = strdup("");
        else if (cJSON_IsString(bpf_filter))
        {
            engine->config.dpdkdump.bpf_filter = strdup(bpf_filter->valuestring);
            if (!engine->config.dpdkdump.bpf_filter)
            {
                set_cjson_parse_error(err, "Memory allocation failed");
                return 0;
            }
        }
        else
        {
            set_cjson_parse_error(err, "invalid dpdkdump.bpf_filter");
            return 0;
        }

        // Ring size
        cJSON *ring_size = cJSON_GetObjectItemCaseSensitive(dpdk_obj, "ring_size");
        if (!ring_size)
            engine->config.dpdkdump.ring_size = 2048;
        else if (cJSON_IsNumber(ring_size))
            engine->config.dpdkdump.ring_size = ring_size->valueint;
        else
        {
            set_cjson_parse_error(err, "invalid dpdkdump.ring_size");
            return 0;
        }
    }
    else
    {
        set_cjson_parse_error(err, "unknown engine type: %s", engine->type);
        return 0;
    }

    return 1;
}

static int parse_output_config(cJSON *output_obj, OutputConfig *output, cJSONParseError *err)
{
    // Common fields
    cJSON *type = cJSON_GetObjectItemCaseSensitive(output_obj, "type");
    if (!cJSON_IsString(type))
    {
        set_cjson_parse_error(err, "missing or invalid output type");
        return 0;
    }
    output->type = strdup(type->valuestring);
    if (!output->type)
    {
        set_cjson_parse_error(err, "memory allocation failed");
        return 0;
    }

    cJSON *rate_limit = cJSON_GetObjectItemCaseSensitive(output_obj, "rate_limit_mbps");
    if (!rate_limit)
        output->rate_limit_mbps = 0;
    else if (cJSON_IsNumber(rate_limit))
        output->rate_limit_mbps = rate_limit->valueint;
    else
    {
        set_cjson_parse_error(err, "invalid rate_limit_mbps");
        return 0;
    }

    cJSON *slice = cJSON_GetObjectItemCaseSensitive(output_obj, "slice");
    if (!slice)
        output->slice = 0;
    else if (cJSON_IsNumber(slice))
        output->slice = slice->valueint;
    else
    {
        set_cjson_parse_error(err, "invalid slice");
        return 0;
    }

    // Type specific config
    if (strcmp(output->type, "vxlan") == 0)
    {
        cJSON *vxlan_obj = cJSON_GetObjectItemCaseSensitive(output_obj, "vxlan");
        if (!vxlan_obj)
        {
            set_cjson_parse_error(err, "missing vxlan config");
            return 0;
        }

        // Remote IPs
        cJSON *ips = cJSON_GetObjectItemCaseSensitive(vxlan_obj, "remote_ips");
        output->config.vxlan.remote_ips = parse_string_array(ips, &output->config.vxlan.remote_ip_count, err);
        if (!output->config.vxlan.remote_ips)
        {
            wrap_cjson_parse_error(err, "invalid vxlan.remote_ips");
            return 0;
        }

        // Port
        cJSON *port = cJSON_GetObjectItemCaseSensitive(vxlan_obj, "port");
        if (!port)
            output->config.vxlan.port = 4789;
        else if (cJSON_IsNumber(port))
            output->config.vxlan.port = port->valueint;
        else
        {
            set_cjson_parse_error(err, "invalid vxlan.port");
            return 0;
        }

        // Capture time
        cJSON *capture_time = cJSON_GetObjectItemCaseSensitive(vxlan_obj, "capture_time");
        if (!capture_time)
            output->config.vxlan.capture_time = 0;
        if (cJSON_IsBool(capture_time))
            output->config.vxlan.capture_time = cJSON_IsTrue(capture_time);
        else
        {
            set_cjson_parse_error(err, "invalid vxlan.capture_time");
            return 0;
        }

        // VNI1 and VNI2
        cJSON *vni1 = cJSON_GetObjectItemCaseSensitive(vxlan_obj, "vni1");
        cJSON *vni2 = cJSON_GetObjectItemCaseSensitive(vxlan_obj, "vni2");
        if (!vni1)
        {
            if (cJSON_IsNumber(vni1))
            {
                output->config.vxlan.version = 1;
                output->config.vxlan.vni = vni1->valueint;
            }
            else
            {
                set_cjson_parse_error(err, "invalid vxlan.vni1");
                return 0;
            }
        }
        else if (!vni2)
        {
            if (cJSON_IsNumber(vni2))
            {
                output->config.vxlan.version = 2;
                output->config.vxlan.vni = vni2->valueint;
            }
            else
            {
                set_cjson_parse_error(err, "invalid vxlan.vni2");
                return 0;
            }
        }
        else
        {
            output->config.vxlan.version = 0;
        }

        // Bind device
        cJSON *bind = cJSON_GetObjectItemCaseSensitive(vxlan_obj, "bind_to_device");
        if (!bind)
            output->config.vxlan.bind_device = strdup("");
        if (cJSON_IsString(bind))
            output->config.vxlan.bind_device = strdup(bind->valuestring);
        else
        {
            set_cjson_parse_error(err, "invalid vxlan.bind_to_device");
            return 0;
        }
    }
    else if (strcmp(output->type, "gre") == 0)
    {
        cJSON *gre_obj = cJSON_GetObjectItemCaseSensitive(output_obj, "gre");
        if (!gre_obj)
        {
            set_cjson_parse_error(err, "missing gre config");
            return 0;
        }

        // Remote IPs
        cJSON *ips = cJSON_GetObjectItemCaseSensitive(gre_obj, "remote_ips");
        output->config.gre.remote_ips = parse_string_array(ips, &output->config.gre.remote_ip_count, err);
        if (!output->config.gre.remote_ips)
        {
            wrap_cjson_parse_error(err, "invalid gre.remote_ips");
            return 0;
        }

        // Port
        cJSON *keybit = cJSON_GetObjectItemCaseSensitive(gre_obj, "keybit");
        if (!keybit)
            output->config.gre.keybit = 0xffffffff;
        else if (cJSON_IsNumber(keybit))
            output->config.gre.keybit = keybit->valueint;
        else
        {
            set_cjson_parse_error(err, "invalid gre.keybit");
            return 0;
        }

        // Bind device
        cJSON *bind = cJSON_GetObjectItemCaseSensitive(gre_obj, "bind_to_device");
        if (!bind)
            output->config.gre.bind_device = strdup("");
        if (cJSON_IsString(bind))
            output->config.gre.bind_device = strdup(bind->valuestring);
        else
        {
            set_cjson_parse_error(err, "invalid gre.bind_to_device");
            return 0;
        }
    }
    else if (strcmp(output->type, "zmq") == 0)
    {
        cJSON *zmq_obj = cJSON_GetObjectItemCaseSensitive(output_obj, "zmq");
        if (!zmq_obj)
        {
            set_cjson_parse_error(err, "missing zmq config");
            return 0;
        }

        // Remote IPs
        cJSON *ips = cJSON_GetObjectItemCaseSensitive(zmq_obj, "remote_ips");
        output->config.zmq.remote_ips = parse_string_array(ips, &output->config.zmq.remote_ip_count, err);
        if (!output->config.zmq.remote_ips)
        {
            wrap_cjson_parse_error(err, "invalid zmq.remote_ips");
            return 0;
        }

        // Port
        cJSON *port = cJSON_GetObjectItemCaseSensitive(zmq_obj, "port");
        if (!port)
            output->config.zmq.port = 4789;
        else if (cJSON_IsNumber(port))
            output->config.zmq.port = port->valueint;
        else
        {
            set_cjson_parse_error(err, "invalid zmq.port");
            return 0;
        }

        // High Watermark
        cJSON *hwm = cJSON_GetObjectItemCaseSensitive(zmq_obj, "hwm");
        if (!hwm)
            output->config.zmq.hwm = 100;
        if (cJSON_IsNumber(hwm))
            output->config.zmq.hwm = hwm->valueint;
        else
        {
            set_cjson_parse_error(err, "invalid zmq.hwm");
            return 0;
        }
    }
    else
    {
        set_cjson_parse_error(err, "Unknown output type: %s", output->type);
        return 0;
    }

    return 1;
}

static TaskConfig *parse_task(cJSON *task_obj, cJSONParseError *err)
{
    TaskConfig *task = (TaskConfig *)calloc(1, sizeof(TaskConfig));
    if (!task)
    {
        set_cjson_parse_error(err, "memory allocation failed");
        return NULL;
    }

    // Parse interface
    cJSON *interface = cJSON_GetObjectItemCaseSensitive(task_obj, "interface");
    if (!cJSON_IsString(interface))
    {
        set_cjson_parse_error(err, "missing or invalid interface");
        goto error;
    }
    task->interface = strdup(interface->valuestring);
    if (!task->interface)
    {
        set_cjson_parse_error(err, "memory allocation failed");
        goto error;
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
            set_cjson_parse_error(err, "memory allocation failed");
            goto error;
        }
    }
    else
    {
        set_cjson_parse_error(err, "invalid netns");
        goto error;
    }

    // Parse engine
    cJSON *engine = cJSON_GetObjectItemCaseSensitive(task_obj, "engine");
    if (!cJSON_IsObject(engine))
    {
        set_cjson_parse_error(err, "missing or invalid engine config");
        goto error;
    }
    if (!parse_engine_config(engine, &task->engine, err))
    {
        wrap_cjson_parse_error(err, "parse engine error");
        goto error;
    }

    // Parse output
    cJSON *output = cJSON_GetObjectItemCaseSensitive(task_obj, "output");
    if (!cJSON_IsObject(output))
    {
        set_cjson_parse_error(err, "missing or invalid output config");
        goto error;
    }
    if (!parse_output_config(output, &task->output, err))
    {
        wrap_cjson_parse_error(err, "parse output error");
        goto error;
    }

    return task;

error:
    free_task(task);
    return NULL;
}

TaskSetConfig *parse_tasks_config(char *data, cJSONParseError *err)
{
    cJSON *json = cJSON_Parse(data);
    if (!json)
    {
        set_cjson_parse_error(err, "JSON parse error before: %s", cJSON_GetErrorPtr());
        return NULL;
    }

    TaskSetConfig *config = (TaskSetConfig *)calloc(1, sizeof(TaskSetConfig));
    if (!config)
    {
        set_cjson_parse_error(err, "memory allocation failed");
        cJSON_Delete(json);
        return NULL;
    }

    cJSON *tasks = cJSON_GetObjectItemCaseSensitive(json, "tasks");
    if (!cJSON_IsArray(tasks))
    {
        set_cjson_parse_error(err, "missing or invalid tasks array");
        goto error;
    }

    int num_tasks = cJSON_GetArraySize(tasks);
    config->tasks = (TaskConfig **)calloc(num_tasks, sizeof(TaskConfig *));
    if (!config->tasks)
    {
        set_cjson_parse_error(err, "memory allocation failed");
        goto error;
    }

    for (int i = 0; i < num_tasks; i++)
    {
        cJSON *task_obj = cJSON_GetArrayItem(tasks, i);
        if (!cJSON_IsObject(task_obj))
        {
            set_cjson_parse_error(err, "task %d is not an object", i);
            goto error;
        }

        TaskConfig *task = parse_task(task_obj, err);
        if (!task)
        {
            printf(err->message);
            printf("\n %d \n", config->num_tasks);
            wrap_cjson_parse_error(err, "parse task %d error", i);
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
        set_cjson_parse_error(error, "failed to open file: %s", filename);
        return NULL;
    }

    fseek(fp, 0, SEEK_END);
    long length = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (length <= 0)
    {
        set_cjson_parse_error(error, "empty file: %s", filename);
        fclose(fp);
        return NULL;
    }

    char *buffer = (char *)malloc(length + 1);
    if (!buffer)
    {
        set_cjson_parse_error(error, "memory allocation failed for file buffer");
        fclose(fp);
        return NULL;
    }

    if (fread(buffer, 1, length, fp) != (size_t)length)
    {
        set_cjson_parse_error(error, "partial read of file: %s", filename);
        free(buffer);
        fclose(fp);
        return NULL;
    }

    buffer[length] = '\0';
    fclose(fp);
    return buffer;
}

TaskSetConfig *parse_tasks_file(const char *filename, cJSONParseError *err)
{
    char *json_str = read_file_contents(filename, err);
    if (!json_str)
        return NULL;

    TaskSetConfig *config = parse_tasks_config(json_str, err);
    free(json_str);
    return config;
}
