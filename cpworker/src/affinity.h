#ifndef CPWORKER_AFFINITY_H
#define CPWORKER_AFFINITY_H

#include "build_config.h"

#if defined(OS_LINUX)
#define CPU_AFFINITY_LINUX 1
#include <sched.h>
int cpu_set_parse(cpu_set_t *mask, const char *value);
#else
#define CPU_AFFINITY_NOOP 1
#endif

int set_cpu_affinity(const char *value);

#endif /* CPWORKER_AFFINITY_H */