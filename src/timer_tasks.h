//
// Created by root on 12/29/20.
//

#ifndef PKTMINERG_TIMER_TASKS_H
#define PKTMINERG_TIMER_TASKS_H

#include <stdint.h>

#define TICK_US_SEC (1000000)
#define TICK_US_MS (1000)
#define TP_INVALID ((uint64_t)-1)
#define TID_INVALID ((uint64_t)-1)

typedef void (*task_cb_t)(void*);
typedef struct timer_tasks timer_tasks_t;

timer_tasks_t* timer_tasks_new();
uint64_t timer_tasks_push(timer_tasks_t* tasks, task_cb_t cb, void* user = 0, uint64_t period = TP_INVALID);
void timer_tasks_run(timer_tasks_t* tasks);
void timer_tasks_stop(timer_tasks_t* tasks);
void timer_tasks_term(timer_tasks_t* tasks);
void timer_tasks_cancel(timer_tasks_t* tasks, uint64_t tid);

#endif //PKTMINERG_TIMER_TASKS_H
