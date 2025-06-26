#include "affinity.h"

#if defined(CPU_AFFINITY_NOOP)

int set_cpu_affinity(char *value) { return 0; }

#endif