#ifndef CPWORKER_UNIX_RPC_BASIC_H
#define CPWORKER_UNIX_RPC_BASIC_H

#include <time.h>

#include "cJSON/cJSON.h"

void unix_rpc_basic_set_started_at(time_t when);
void unix_rpc_basic_set_config_path(const char *path);
void unix_rpc_basic_set_working_dir(const char *cwd);

int unix_rpc_ping_command(cJSON *cmd_msg, cJSON *server_msg, void *data);
int unix_rpc_info_command(cJSON *cmd_msg, cJSON *server_msg, void *data);

#endif
