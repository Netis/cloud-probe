#include "taskconf.h"
#include "cJSON/cJSON.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PARSE_ERROR -1

static void free_output(OutputConfig *output)
{
    if (!output)
        return;

    if (output->type)
    {

        if (strcmp(output->type, "vxlan") == 0)
        {
            free(output->config.vxlan.host);
            free(output->config.vxlan.bind_device);
        }
        else if (strcmp(output->type, "gre") == 0)
        {
            free(output->config.gre.host);
            free(output->config.gre.bind_device);
        }
        else if (strcmp(output->type, "zmq") == 0)
        {
            free(output->config.zmq.host);
        }
    }

    free(output->type);
    return;
}

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

    for (int i = 0; i < task->num_outputs; i++)
        free_output(task->outputs[i]);

    free(task->engine.type);
    free(task->interface);
    free(task->netns);
    free(task->outputs);
    free(task);
}

void free_tasks_config(TasksAllConfig *config)
{
    if (!config)
        return;

    for (int i = 0; i < config->num_tasks; i++)
        free_task(config->tasks[i]);

    free(config->tasks);
    free(config);
}

static int parse_engine_config(cJSON *engine_obj, EngineConfig *engine, cJSONParseError *err)
{
    cJSON *type = cJSON_GetObjectItemCaseSensitive(engine_obj, "type");
    if (!cJSON_IsString(type))
    {
        set_cjson_parse_error(err, "missing or invalid engine type");
        return PARSE_ERROR;
    }

    engine->type = strdup(type->valuestring);
    if (!engine->type)
    {
        set_cjson_parse_error(err, "memory allocation failed");
        return PARSE_ERROR;
    }

    if (strcmp(engine->type, "libpcap") == 0)
    {
        cJSON *libpcap_obj = cJSON_GetObjectItemCaseSensitive(engine_obj, "libpcap");
        if (!libpcap_obj)
        {
            set_cjson_parse_error(err, "missing libpcap config");
            return PARSE_ERROR;
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
            return PARSE_ERROR;
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
                return PARSE_ERROR;
            }
        }
        else
        {
            set_cjson_parse_error(err, "invalid libpcap.bpf_filter");
            return PARSE_ERROR;
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
            return PARSE_ERROR;
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
            return PARSE_ERROR;
        }
    }
    else if (strcmp(engine->type, "dpdkdump") == 0)
    {
        cJSON *dpdk_obj = cJSON_GetObjectItemCaseSensitive(engine_obj, "dpdkdump");
        if (!dpdk_obj)
        {
            set_cjson_parse_error(err, "missing dpdkdump config");
            return PARSE_ERROR;
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
            return PARSE_ERROR;
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
                return PARSE_ERROR;
            }
        }
        else
        {
            set_cjson_parse_error(err, "invalid dpdkdump.bpf_filter");
            return PARSE_ERROR;
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
            return PARSE_ERROR;
        }
    }
    else
    {
        set_cjson_parse_error(err, "unknown engine type: %s", engine->type);
        return PARSE_ERROR;
    }

    return 0;
}

static int parse_output_config(cJSON *output_obj, OutputConfig *output, cJSONParseError *err)
{
    // Common fields
    cJSON *type = cJSON_GetObjectItemCaseSensitive(output_obj, "type");
    if (!cJSON_IsString(type))
    {
        set_cjson_parse_error(err, "missing or invalid output type");
        return PARSE_ERROR;
    }
    output->type = strdup(type->valuestring);
    if (!output->type)
    {
        set_cjson_parse_error(err, "memory allocation failed");
        return PARSE_ERROR;
    }

    cJSON *rate_limit = cJSON_GetObjectItemCaseSensitive(output_obj, "rate_limit_mbps");
    if (!rate_limit)
        output->rate_limit_mbps = 0;
    else if (cJSON_IsNumber(rate_limit))
        output->rate_limit_mbps = rate_limit->valueint;
    else
    {
        set_cjson_parse_error(err, "invalid rate_limit_mbps");
        return PARSE_ERROR;
    }

    cJSON *slice = cJSON_GetObjectItemCaseSensitive(output_obj, "slice");
    if (!slice)
        output->slice = 0;
    else if (cJSON_IsNumber(slice))
        output->slice = slice->valueint;
    else
    {
        set_cjson_parse_error(err, "invalid slice");
        return PARSE_ERROR;
    }

    // Type specific config
    if (strcmp(output->type, "vxlan") == 0)
    {
        cJSON *vxlan_obj = cJSON_GetObjectItemCaseSensitive(output_obj, "vxlan");
        if (!vxlan_obj)
        {
            set_cjson_parse_error(err, "missing vxlan config");
            return PARSE_ERROR;
        }

        // host
        cJSON *host = cJSON_GetObjectItemCaseSensitive(vxlan_obj, "host");
        if (!cJSON_IsString(host))
        {
            wrap_cjson_parse_error(err, "missing or invalid vxlan.host");
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
            set_cjson_parse_error(err, "invalid vxlan.port");
            return PARSE_ERROR;
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
            return PARSE_ERROR;
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
                return PARSE_ERROR;
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
                return PARSE_ERROR;
            }
        }
        else
        {
            output->config.vxlan.version = 0;
        }

        // Bind device
        cJSON *bind = cJSON_GetObjectItemCaseSensitive(vxlan_obj, "bind_device");
        if (!bind)
            output->config.vxlan.bind_device = strdup("");
        if (cJSON_IsString(bind))
            output->config.vxlan.bind_device = strdup(bind->valuestring);
        else
        {
            set_cjson_parse_error(err, "invalid vxlan.bind_device");
            return PARSE_ERROR;
        }
    }
    else if (strcmp(output->type, "gre") == 0)
    {
        cJSON *gre_obj = cJSON_GetObjectItemCaseSensitive(output_obj, "gre");
        if (!gre_obj)
        {
            set_cjson_parse_error(err, "missing gre config");
            return PARSE_ERROR;
        }

        cJSON *host = cJSON_GetObjectItemCaseSensitive(gre_obj, "host");
        if (!cJSON_IsString(host))
        {
            wrap_cjson_parse_error(err, "missing or invalid gre.host");
            return PARSE_ERROR;
        }
        output->config.gre.host = strdup(host->valuestring);

        // Keybit
        cJSON *keybit = cJSON_GetObjectItemCaseSensitive(gre_obj, "keybit");
        if (!keybit)
            output->config.gre.keybit = 0xffffffff;
        else if (cJSON_IsNumber(keybit))
            output->config.gre.keybit = keybit->valueint;
        else
        {
            set_cjson_parse_error(err, "invalid gre.keybit");
            return PARSE_ERROR;
        }

        // Bind device
        cJSON *bind = cJSON_GetObjectItemCaseSensitive(gre_obj, "bind_device");
        if (!bind)
            output->config.gre.bind_device = strdup("");
        if (cJSON_IsString(bind))
            output->config.gre.bind_device = strdup(bind->valuestring);
        else
        {
            set_cjson_parse_error(err, "invalid gre.bind_device");
            return PARSE_ERROR;
        }
    }
    else if (strcmp(output->type, "zmq") == 0)
    {
        cJSON *zmq_obj = cJSON_GetObjectItemCaseSensitive(output_obj, "zmq");
        if (!zmq_obj)
        {
            set_cjson_parse_error(err, "missing zmq config");
            return PARSE_ERROR;
        }

        // Host
        cJSON *host = cJSON_GetObjectItemCaseSensitive(zmq_obj, "host");
        if (!cJSON_IsString(host))
        {
            wrap_cjson_parse_error(err, "missing or invalid zmq.host");
            return PARSE_ERROR;
        }
        output->config.zmq.host = strdup(host->valuestring);

        // Port
        cJSON *port = cJSON_GetObjectItemCaseSensitive(zmq_obj, "port");
        if (!port)
            output->config.zmq.port = 4789;
        else if (cJSON_IsNumber(port))
            output->config.zmq.port = port->valueint;
        else
        {
            set_cjson_parse_error(err, "invalid zmq.port");
            return PARSE_ERROR;
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
            return PARSE_ERROR;
        }

        // Keybit
        cJSON *keybit = cJSON_GetObjectItemCaseSensitive(zmq_obj, "keybit");
        if (!keybit)
            output->config.zmq.keybit = 0xffffffff;
        else if (cJSON_IsNumber(keybit))
            output->config.zmq.keybit = keybit->valueint;
        else
        {
            set_cjson_parse_error(err, "invalid zmq.keybit");
            return PARSE_ERROR;
        }
    }
    else
    {
        set_cjson_parse_error(err, "Unknown output type: %s", output->type);
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
        set_cjson_parse_error(err, "missing or invalid interface");
        return PARSE_ERROR;
    }
    task->interface = strdup(interface->valuestring);
    if (!task->interface)
    {
        set_cjson_parse_error(err, "memory allocation failed");
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
            set_cjson_parse_error(err, "memory allocation failed");
            return PARSE_ERROR;
        }
    }
    else
    {
        set_cjson_parse_error(err, "invalid netns");
        return PARSE_ERROR;
    }

    // Parse engine
    cJSON *engine = cJSON_GetObjectItemCaseSensitive(task_obj, "engine");
    if (!cJSON_IsObject(engine))
    {
        set_cjson_parse_error(err, "missing or invalid engine config");
        return PARSE_ERROR;
    }
    if (parse_engine_config(engine, &task->engine, err) != 0)
    {
        wrap_cjson_parse_error(err, "parse engine error");
        return PARSE_ERROR;
    }

    // Parse outputs
    cJSON *outputs = cJSON_GetObjectItemCaseSensitive(task_obj, "outputs");
    if (!cJSON_IsArray(outputs))
    {
        set_cjson_parse_error(err, "missing or invalid outputs config");
        return PARSE_ERROR;
    }

    int num_outputs = cJSON_GetArraySize(outputs);
    task->outputs = (OutputConfig **)calloc(num_outputs, sizeof(OutputConfig *));
    if (!task->outputs)
    {
        set_cjson_parse_error(err, "memory allocation failed");
        return PARSE_ERROR;
    }

    for (int i = 0; i < num_outputs; i++)
    {
        cJSON *output_obj = cJSON_GetArrayItem(outputs, i);
        if (!cJSON_IsObject(output_obj))
        {
            set_cjson_parse_error(err, "output %d is not an object", i);
            return PARSE_ERROR;
        }

        OutputConfig *output = (OutputConfig *)calloc(1, sizeof(OutputConfig));
        if (!output)
        {
            set_cjson_parse_error(err, "memory allocation failed");
            return PARSE_ERROR;
        }
        if (parse_output_config(output_obj, output, err) != 0)
        {
            free_output(output);
            wrap_cjson_parse_error(err, "parse output error");
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
        set_cjson_parse_error(err, "JSON parse error before: %s", cJSON_GetErrorPtr());
        return NULL;
    }

    TasksAllConfig *config = (TasksAllConfig *)calloc(1, sizeof(TasksAllConfig));
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

        TaskConfig *task = (TaskConfig *)calloc(1, sizeof(TaskConfig));
        if (!task)
        {
            set_cjson_parse_error(err, "memory allocation failed");
            goto error;
        }

        if (parse_task_config(task_obj, task, err) != 0)
        {
            free_task(task);
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

TasksAllConfig *parse_tasks_file(const char *filename, cJSONParseError *err)
{
    char *json_str = read_file_contents(filename, err);
    if (!json_str)
        return NULL;

    TasksAllConfig *config = parse_tasks_config(json_str, err);
    free(json_str);
    return config;
}
