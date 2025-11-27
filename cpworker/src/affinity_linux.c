#include "affinity.h"

#if defined(CPU_AFFINITY_LINUX)

#include <sched.h>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>

int cpu_set_parse(cpu_set_t *mask, const char *value)
{
    char *end = 0;
    const char *pos = value;
    unsigned long v0, v1;

    CPU_ZERO(mask);

    while (*pos)
    {
        if (!isdigit((unsigned char)*pos))
            return -1;
        v0 = strtoul(pos, &end, 0);
        if (end == pos)
            return -1;
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
            if (end == pos)
                return -1;
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
            if (!*pos)
                return -1;
        }
        else if (*pos)
            return -1;
    }
    return 0;
}

int set_cpu_affinity(const char *value)
{
    if (value == NULL)
        return -1;

    cpu_set_t mask;
    if (cpu_set_parse(&mask, value) != 0)
        return -1;

    return sched_setaffinity(0, sizeof(cpu_set_t), &mask);
}

#endif