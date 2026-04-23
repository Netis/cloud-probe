#ifndef CPWORKER_UNIX_MANAGER_H
#define CPWORKER_UNIX_MANAGER_H

#include "cJSON/cJSON.h"

int unix_manager_init(const char *socket_file);
int unix_manager_register_command(const char *cmd_name, int (*func)(cJSON *, cJSON *, void *), void *data);

int unix_manager_thread_spawn();

/* Applies SO_SNDTIMEO to fd. Returns 0 on success. A slow reader causes
 * subsequent send() calls to fail with EAGAIN after the timeout instead of
 * stalling the manager thread indefinitely. Exposed for tests. */
int unix_manager_set_send_timeout(int fd, int seconds);

#endif /* CPWORKER_UNIX_MANAGER_H */
