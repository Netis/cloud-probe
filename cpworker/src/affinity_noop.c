#include "affinity.h"

#if defined(CPU_AFFINITY_NOOP)

int set_cpu_affinity(int cpu) { return 0; }

#endif