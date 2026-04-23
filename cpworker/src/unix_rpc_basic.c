#include "unix_rpc_basic.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "build_config.h"

static time_t g_started_at = 0;
static const char *g_config_path = NULL;
static char *g_working_dir = NULL;

void unix_rpc_basic_set_started_at(time_t when) { g_started_at = when; }

void unix_rpc_basic_set_config_path(const char *path) { g_config_path = path; }

void unix_rpc_basic_set_working_dir(const char *cwd)
{
    free(g_working_dir);
    g_working_dir = (cwd != NULL) ? strdup(cwd) : NULL;
}

int unix_rpc_ping_command(cJSON *cmd_msg, cJSON *server_msg, void *data)
{
    (void)cmd_msg;
    (void)data;
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
        return -1;

    int64_t ts_ms = (int64_t)ts.tv_sec * 1000 + (int64_t)(ts.tv_nsec / 1000000);
    if (!cJSON_AddNumberToObject(server_msg, "ts_ms", (double)ts_ms))
        return -1;
    return 0;
}

int unix_rpc_info_command(cJSON *cmd_msg, cJSON *server_msg, void *data)
{
    (void)cmd_msg;
    (void)data;

    if (!cJSON_AddStringToObject(server_msg, "version", CPWORKER_VERSION))
        return -1;
    if (!cJSON_AddNumberToObject(server_msg, "pid", (double)getpid()))
        return -1;

    time_t now = time(NULL);
    int64_t uptime_sec = g_started_at > 0 ? (int64_t)(now - g_started_at) : 0;
    if (!cJSON_AddNumberToObject(server_msg, "uptime_sec", (double)uptime_sec))
        return -1;
    if (!cJSON_AddNumberToObject(server_msg, "started_at_sec", (double)g_started_at))
        return -1;

    const char *cfg = g_config_path != NULL ? g_config_path : "";
    if (!cJSON_AddStringToObject(server_msg, "config_path", cfg))
        return -1;

    const char *wd = g_working_dir != NULL ? g_working_dir : "";
    if (!cJSON_AddStringToObject(server_msg, "working_dir", wd))
        return -1;

    /* cpworker logs to stderr; no log_file config exists. */
    if (!cJSON_AddStringToObject(server_msg, "log_destination", "stderr"))
        return -1;

    return 0;
}
