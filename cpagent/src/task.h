#ifndef CPAGENT_TASK_H
#define CPAGENT_TASK_H

#include "capturer.h"
#include "output.h"
#include "taskconf.h"

typedef struct CaptureTask
{
    capturer_base_t *capturer;
    output_base_t **outputs;
    int num_outputs;
} capture_task_t;

capture_task_t *capture_task_new(TaskConfig *task_cfg, char *errbuf);
void capture_task_destory(capture_task_t *task);
int capture_task_poll_packets(capture_task_t *task);

#endif /* CPAGENT_TASK_H */