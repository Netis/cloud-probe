#!/bin/sh

MAJOR_VERSION=0
if [ -e /etc/centos-release ]; then
    MAJOR_VERSION=`rpm -q --queryformat '%{VERSION}' centos-release`
fi

cgroup_pktg_cpuset() {
    CPU_SET_ID=$1

    if [ $MAJOR_VERSION = "6" ]; then
        cd /cgroup/cpuset
    else
        cd /sys/fs/cgroup/cpuset
    fi
    mkdir -p pktg
    cd pktg
    echo $CPU_SET_ID > cpuset.cpus
    echo 0 > cpuset.mems

    for pid in `ps -ef | grep pktminerg | grep -v grep | awk '{print $2}'` ; do echo $pid > cgroup.procs; done
}

cgroup_pktg_cpu() {
    CFS_QUOTA_US=$1

    if [ $MAJOR_VERSION = "6" ]; then
        cd /cgroup/cpu
    else
        cd /sys/fs/cgroup/cpu
    fi
    mkdir -p pktg
    cd pktg

    echo $CFS_QUOTA_US > cpu.cfs_quota_us

    for pid in `ps -ef | grep pktminerg | grep -v grep | awk '{print $2}'` ; do echo $pid > cgroup.procs; done
}

cgroup_pktg_mem() {
    MEM_LIMIT=$1

    if [ $MAJOR_VERSION = "6" ]; then
        cd /cgroup/memory
    else
        cd /sys/fs/cgroup/memory
    fi
    mkdir -p pktg
    cd pktg

    echo $MEM_LIMIT > memory.limit_in_bytes

    for pid in `ps -ef | grep pktminerg | grep -v grep | awk '{print $2}'` ; do echo $pid > cgroup.procs; done
}

cgroup_pktg() {
    cgroup_pktg_cpuset $1
    cgroup_pktg_cpu $2
    cgroup_pktg_mem $3
}


if [ "$3" == "" ]
then
    echo "Usage:"
    echo "    sh limit_cpu_mem.sh CPU_SET_ID CFS_QUOTA_US MEM_LIMIT"
    echo "        CPU_SET_ID: limit pktminerg to run on this cpu processor id."
    echo "        CFS_QUOTA_US: limit the run-time quota of pktminerg within a period(100ms), in microsecond."
    echo "        MEM_LIMIT: limit pktminerg memory usage in bytes, such as 800M, 64K, 1024000"
    echo "Example:"
    echo "    sh limit_cpu_mem.sh 2 30000 800M  # run on cpu2, 30% cpu usage limit, 800MByte memory limit"
else
    cgroup_pktg $1 $2 $3
fi

