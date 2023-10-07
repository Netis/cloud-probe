#!/bin/sh

MAJOR_VERSION=0
if [ -e /etc/centos-release ]; then
    MAJOR_VERSION=`rpm -q --queryformat '%{VERSION}' centos-release`
fi

cgroup_pktg_cpu() {
    CFS_QUOTA_US=$2

    if [ $MAJOR_VERSION = "6" ]; then
        mkdir -p /cgroup/cpu
        cd /cgroup/cpu
    else
        mkdir -p /sys/fs/cgroup/cpu
        cd /sys/fs/cgroup/cpu
    fi
    mkdir -p pid-$1
    cd pid-$1

    if [ $CFS_QUOTA_US != "0" ]; then
        echo $CFS_QUOTA_US > cpu.cfs_quota_us
    fi
    echo $1 > cgroup.procs
}

cgroup_pktg_mem() {
    MEM_LIMIT=$2

    if [ $MAJOR_VERSION = "6" ]; then
        mkdir -p /cgroup/memory
        cd /cgroup/memory
    else
        mkdir -p /sys/fs/cgroup/memory
        cd /sys/fs/cgroup/memory
    fi
    mkdir -p pid-$1
    cd pid-$1

    if [ $MEM_LIMIT != "0" ] && [ $MEM_LIMIT != "0K" ] && [ $MEM_LIMIT != "0M" ] && [ $MEM_LIMIT != "0G" ] && [ $MEM_LIMIT != "0T" ]; then
        echo $MEM_LIMIT > memory.limit_in_bytes
    fi
    echo $1 > cgroup.procs
}

cgroup_pktg() {
    cgroup_pktg_cpu $1 $2
    cgroup_pktg_mem $1 $3
}


if [ "$3" == "" ]
then
    echo "Usage:"
    echo "    sh limit_cpu_mem_pid.sh PID CFS_QUOTA_US MEM_LIMIT"
    echo "        PID: limit process pid."
    echo "        CFS_QUOTA_US: limit the run-time quota of process within a period(100ms), in microsecond."
    echo "        MEM_LIMIT: limit process memory usage in bytes, such as 800M, 64K, 1024000"
    echo "Example:"
    echo "    sh limit_cpu_mem_pid.sh 4856 30000 800M  # 30% cpu usage limit, 800MByte memory limit"
else
    cgroup_pktg $1 $2 $3
fi

