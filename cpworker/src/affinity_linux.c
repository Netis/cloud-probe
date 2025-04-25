#include "affinity.h"

#if defined(CPU_AFFINITY_LINUX)

#ifdef __linux__
#define _GNU_SOURCE // 启用GNU扩展
#include <sched.h>
#endif

int set_cpu_affinity(int cpu)
{
    cpu_set_t cpu_mask;
    CPU_ZERO(&cpu_mask);
    CPU_SET(cpu, &cpu_mask);
    if (sched_setaffinity(0, sizeof(cpu_set_t), &cpu_mask) != 0)
    {
        return -1;
    }
    return 0;
}

#endif