#include "syshelp.h"
#include <sys/resource.h>
#include <unistd.h>
#include <sched.h>
#include "prio.h"

#ifdef __FreeBSD__
	#include <sys/param.h>
	#include <sys/cpuset.h>
	#define cpu_set_t cpuset_t
	#define SET_AFFINITY(pid, size, mask) \
		   cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, -1, size, mask)
	#define GET_AFFINITY(pid, size, mask) \
		   cpuset_getaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, -1, size, mask)
#elif defined(__APPLE__)
	#include <mach/mach_init.h>
	#include <mach/thread_policy.h>
	#include <mach/thread_act.h>

	#define cpu_set_t thread_affinity_policy_data_t
	#define CPU_SET(cpu_id, new_mask) \
		((*(new_mask)).affinity_tag = (cpu_id + 1))
	#define CPU_ZERO(new_mask)                 \
		((*(new_mask)).affinity_tag = THREAD_AFFINITY_TAG_NULL)
	#define GET_AFFINITY(pid, size, mask) \
		 ((*(mask)).affinity_tag = THREAD_AFFINITY_TAG_NULL)
	#define SET_AFFINITY(pid, size, mask)       \
		thread_policy_set(mach_thread_self(), THREAD_AFFINITY_POLICY, \
				  (int *)mask, THREAD_AFFINITY_POLICY_COUNT)
#else
	#define SET_AFFINITY(pid, size, mask) sched_setaffinity(0, size, mask)
	#define GET_AFFINITY(pid, size, mask) sched_getaffinity(0, size, mask)
#endif

#define DEFAULT_PRIORITY -18

// set self proc and all thread to very high priority, return 0 if success
int set_high_setpriority() {
#ifdef MAC
    return 0;
#else
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
#endif
}

// bind cpu to given core, return 0 if success
int set_cpu_affinity(int cpu) {
    cpu_set_t cpu_mask;
    CPU_ZERO(&cpu_mask);
    CPU_SET(cpu, &cpu_mask);
    if (SET_AFFINITY(0, sizeof(cpu_set_t), &cpu_mask) == -1) {
        return -1;
    }
    return 0;
}
