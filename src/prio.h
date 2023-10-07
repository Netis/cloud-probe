#ifndef SRC_PRIO_H_
#define SRC_PRIO_H_

#ifndef WIN32
	#include <unistd.h>
	#include <sys/resource.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

/**
 * prio.h
 *
 * @version 1.0
 * @since project 0.6
 */

int set_high_setpriority();

extern int sys_ioprio_set(int, int, int);
extern int sys_ioprio_get(int, int);

#if defined(__i386__)
#define __NR_ioprio_set         289
#define __NR_ioprio_get         290
#elif defined(__ppc__)
#define __NR_ioprio_set         273
#define __NR_ioprio_get         274
#elif defined(__x86_64__)
#define __NR_ioprio_set         251
#define __NR_ioprio_get         252
#elif defined(__ia64__)
#define __NR_ioprio_set         1274
#define __NR_ioprio_get         1275
#elif defined(__aarch64__)
#define __NR_ioprio_set         30
#define __NR_ioprio_get         31
#else
#error "Unsupported arch"
#endif

static inline int ioprio_set(int which, int who, int ioprio) {
    return syscall(__NR_ioprio_set, which, who, ioprio);
}

static inline int ioprio_get(int which, int who) {
    return syscall(__NR_ioprio_get, which, who);
}

enum {
    IOPRIO_CLASS_NONE,
    IOPRIO_CLASS_RT,
    IOPRIO_CLASS_BE,
    IOPRIO_CLASS_IDLE,
};

enum {
    IOPRIO_WHO_PROCESS = 1,
    IOPRIO_WHO_PGRP,
    IOPRIO_WHO_USER,
};

#define IOPRIO_BITS             (16)
#define IOPRIO_CLASS_SHIFT      (13)
#define IOPRIO_PRIO_MASK        ((1UL << IOPRIO_CLASS_SHIFT) - 1)

#define IOPRIO_PRIO_CLASS(mask) ((mask) >> IOPRIO_CLASS_SHIFT)
#define IOPRIO_PRIO_DATA(mask)  ((mask) & IOPRIO_PRIO_MASK)
#define IOPRIO_PRIO_VALUE(class, data)  (((class) << IOPRIO_CLASS_SHIFT) | data)

#define ioprio_valid(mask)      (IOPRIO_PRIO_CLASS((mask)) != IOPRIO_CLASS_NONE)

#endif // SRC_PRIO_H_
