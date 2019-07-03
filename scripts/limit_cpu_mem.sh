#!/bin/sh

MAJOR_VERSION=0
if [ -e /etc/centos-release ]; then
    MAJOR_VERSION=`rpm -q --queryformat '%{VERSION}' centos-release`
fi

cgroup_pktg_cpu() {
    CPU_ID=$1

    if [ $MAJOR_VERSION = "6" ]; then
        cd /cgroup/cpuset
    else
        cd /sys/fs/cgroup/cpuset
    fi
    mkdir -p pktg
    cd pktg

    echo $CPU_ID > cpuset.cpus
    echo 0 > cpuset.mems

    for pid in `ps -ef | grep pktminerg | grep -v grep | awk '{print $2}'` ; do echo $pid > cgroup.procs; done
}

cgroup_pktg_mem() {
    if [ $MAJOR_VERSION = "6" ]; then
        cd /cgroup/memory
    else
        cd /sys/fs/cgroup/memory
    fi
    mkdir -p pktg
    cd pktg

    echo 800M > memory.limit_in_bytes

    for pid in `ps -ef | grep pktminerg | grep -v grep | awk '{print $2}'` ; do echo $pid > cgroup.procs; done
}

cgroup_pktg() {
    cgroup_pktg_cpu $1
    cgroup_pktg_mem
}


if [ "$1" == "" ]
then
    echo "Usage:"
    echo "    sh limit_cpu_mem.sh CPU_ID"
    echo "        CPU_ID: limit pktminerg to run on this cpu processor id."
    echo "Example:"
    echo "    sh limit_cpu_mem.sh 2"
else
    cgroup_pktg $1
fi

