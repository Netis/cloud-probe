#ifndef CPAGENT_AFFINITY_H
#define CPAGENT_AFFINITY_H

#include "config.h"

#if defined(OS_LINUX)
#define CPU_AFFINITY_LINUX 1
#else
#define CPU_AFFINITY_NOOP 1
#endif

int set_cpu_affinity(int cpu);

#endif /* CPAGENT_AFFINITY_H */