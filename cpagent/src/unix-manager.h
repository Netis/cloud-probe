#ifndef CPAGENT_UNIX_MANAGER_H
#define CPAGENT_UNIX_MANAGER_H

#include "cJSON/cJSON.h"

int unix_manager_init(const char *socket_file);
int unix_manager_register_command(const char *cmd_name, int (*func)(cJSON *, cJSON *, void *), void *data);
int unix_manager_thread_spawn();

#endif /* CPAGENT_UNIX_MANAGER_H */