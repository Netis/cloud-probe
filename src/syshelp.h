#ifndef SRC_SYSHELP_H_
#define SRC_SYSHELP_H_

// set self proc and all thread to very high priority, return 0 if success
int set_high_setpriority();

// bind cpu to given core, return 0 if success
int set_cpu_affinity(int);

#endif // SRC_SYSHELP_H_
