#ifndef CPWORKER_TASK_H
#define CPWORKER_TASK_H

#include "capturer.h"
#include "config.h"
#include "output.h"

typedef struct CaptureTask
{
    capturer_base_t *capturer;
    output_base_t **outputs;
    int num_outputs;
} capture_task_t;

capture_task_t *capture_task_new(TaskConfig *task_cfg, char *errbuf);
void capture_task_destory(capture_task_t *task);
uint64_t capture_task_poll_packets(capture_task_t *task);

int task_manager_init(TasksAllConfig *config);
void task_manager_destory();
uint64_t task_manager_poll_packets();
void task_manager_update_stats();
int task_manager_collect_stats_summary_command(cJSON *cmd_msg, cJSON *server_msg, void *data);
int task_manager_collect_stats_detail_command(cJSON *cmd_msg, cJSON *server_msg, void *data);

#endif /* CPWORKER_TASK_H */