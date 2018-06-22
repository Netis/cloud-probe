#include "syshelp.h"
#include <sys/resource.h>
#include <unistd.h>
#include <sched.h>
#include "prio.h"

#define DEFAULT_PRIORITY -18

// set self proc and all thread to very high priority, return 0 if success
int set_high_setpriority() {
    int rc;
    pid_t pgid;

    if ((pgid = getpgrp()) < 0) {
        return -1;
    }

    rc = setpriority(PRIO_PGRP, 0, DEFAULT_PRIORITY);
    ioprio_set(IOPRIO_WHO_PGRP, 0, 0 | IOPRIO_CLASS_RT << IOPRIO_CLASS_SHIFT);
    if (rc != 0) {
        return -1;
    }

    return rc;
}

// bind cpu to given core, return 0 if success
int set_cpu_affinity(int cpu) {
    cpu_set_t cpu_mask;
    CPU_ZERO(&cpu_mask);
    CPU_SET(cpu, &cpu_mask);
    if (sched_setaffinity(0, sizeof(cpu_set_t), &cpu_mask) == -1) {
        return -1;
    }
    return 0;
}