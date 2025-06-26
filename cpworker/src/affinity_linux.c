#include "affinity.h"

#if defined(CPU_AFFINITY_LINUX)

#ifdef __linux__
#define _GNU_SOURCE // 启用GNU扩展
#include <sched.h>
#endif

#include <stdio.h>
#include <stdlib.h>

int cpu_set_parse(cpu_set_t *mask, char *value)
{
    char *end = 0;
    char *pos = value;
    unsigned long v0, v1;

    CPU_ZERO(mask);

    while (*pos)
    {
        v0 = strtoul(pos, &end, 0);
        v1 = v0;
        pos = end;
        if (!*pos)
        {
            CPU_SET(v0, mask);
            return 0;
        }
        if (*pos == '-')
        {
            ++pos;
            v1 = strtoul(pos, &end, 0);
            if (v0 > v1)
                return -1;
            pos = end;
        }
        if (*pos == ',' || !*pos)
        {
            for (unsigned long v = v0; v <= v1; ++v)
                CPU_SET(v, mask);
            if (!*pos)
                return 0;
            ++pos;
        }
        else if (*pos)
            return -1;
    }
    return 0;
}

int set_cpu_affinity(char *value)
{
    cpu_set_t mask;
    if (cpu_set_parse(&mask, value) != 0)
        return -1;

    return sched_setaffinity(0, sizeof(cpu_set_t), &mask);
}

#endif