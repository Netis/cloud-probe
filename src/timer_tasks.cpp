//
// Created by root on 12/29/20.
//
#include "timer_tasks.h"
#include <unistd.h>
#include <stddef.h>
#include <string.h>
#include <sys/time.h>
#include <vector>
#include <set>
#include <mutex>
#include <thread>

typedef struct
{
    uint64_t tick_us;
    uint64_t period;
    uint64_t tid;
    void* user;
    task_cb_t cb;
}timer_task_t;

typedef struct
{
    bool
    operator()(const timer_task_t& __x, const timer_task_t& __y) const
    {
        if(__x.tick_us < __y.tick_us)
            return true;
        if(__x.tick_us > __y.tick_us)
            return false;

        return memcmp((char*)&__x + offsetof(timer_task_t, period),
                      (char*)&__y + offsetof(timer_task_t, period),
                      sizeof(timer_task_t) - offsetof(timer_task_t, period)) <= 0;

    }
}timer_task_cmp_t;

struct timer_tasks
{
    uint64_t idx;
    int loop;
    std::mutex mtx;
    std::set<timer_task_t, timer_task_cmp_t> tasks;
    std::set<uint64_t> cancel_tids;
};

inline uint64_t timer_tasks_now_us() {
    uint64_t now_us;
    timeval tv;
    gettimeofday(&tv, 0);
    now_us = tv.tv_sec * TICK_US_SEC + tv.tv_usec;
    return now_us;
}

void timer_tasks_step(timer_tasks_t *tasks) {
    std::set<timer_task_t, timer_task_cmp_t>::iterator it;
    uint64_t now_us;
    std::vector<timer_task_t> tick_tasks;
    std::vector<timer_task_t> period_tasks;

    now_us = timer_tasks_now_us();
    {
        std::lock_guard<std::mutex> lock{tasks->mtx};

        for(it = tasks->tasks.begin(); it != tasks->tasks.end();)
        {
            if(tasks->cancel_tids.find(it->tid) != tasks->cancel_tids.end())
            {
                tasks->cancel_tids.erase(it->tid);
                tasks->tasks.erase(it++);
            }
            else
                ++it;
        }

        for (it = tasks->tasks.begin(); it != tasks->tasks.end();) {
            if (it->tick_us <= now_us) {
                tick_tasks.push_back(*it);
                tasks->tasks.erase(it++);
            } else
                break;
        }
    }
    if(tick_tasks.size())
    {
        for(auto& tick_task : tick_tasks) {
            tick_task.cb(tick_task.user);
            if(tick_task.period != TP_INVALID)
            {
                tick_task.tick_us += tick_task.period;
                period_tasks.push_back(tick_task);
            }
        }
    }
    {
        std::lock_guard<std::mutex> lock{tasks->mtx};
        for(auto& period_task : period_tasks)
        {
            //period_task.tick_us += period_task.period;
            tasks->tasks.emplace(period_task);
        }
    }
    if(!tick_tasks.size())
        usleep(TICK_US_MS * 50);
}

void timer_tasks_run(timer_tasks_t *tasks) {
    while(tasks->loop)
        timer_tasks_step(tasks);
}

void timer_tasks_term(timer_tasks_t *tasks) {
    delete tasks;
}


void timer_tasks_stop(timer_tasks_t* tasks)
{
    tasks->loop = 0;
}

uint64_t timer_tasks_push(timer_tasks_t* tasks, task_cb_t cb, void* user, uint64_t period) {
    uint64_t tick_us = timer_tasks_now_us();

    timer_task_t task = {tick_us, period, tasks->idx, user, cb};

    std::lock_guard<std::mutex> lock{tasks->mtx};
    tasks->tasks.emplace(task);
    ++tasks->idx;
    return task.tid;
}

timer_tasks_t* timer_tasks_new(){
    timer_tasks_t* tasks;
    if(!(tasks = new(std::nothrow) timer_tasks_t))
        return 0;
    tasks->loop = 1;
    tasks->idx = 0;
    return tasks;
}

void timer_tasks_cancel(timer_tasks_t *tasks, uint64_t tid) {
    std::lock_guard<std::mutex> lock{tasks->mtx};
    tasks->cancel_tids.emplace(tid);
}
