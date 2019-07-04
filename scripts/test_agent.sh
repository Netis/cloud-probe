#!/bin/sh

REPLAY_ETH=eth1
GRE_RECV_IP=192.168.1.11
PKTG_CPU_ID=1

SHELL_FOLDER=`pwd`
MAJOR_VERSION=0
if [ -e /etc/centos-release ]; then
    MAJOR_VERSION=`rpm -q --queryformat '%{VERSION}' centos-release`
fi

cgroup_tcpreplay() {
    if [ $MAJOR_VERSION = "6" ]; then
        cd /cgroup/cpuset
    else
        cd /sys/fs/cgroup/cpuset
    fi
	mkdir -p tcpreplay
	cd tcpreplay
	 
	echo 0 > cpuset.cpus
	echo 0 > cpuset.mems
	 
	for pid in `ps -ef | grep tcpreplay | grep -v grep | awk '{print $2}'` ; do echo $pid > cgroup.procs; done
}

cgroup_pktg() {
    if [ $MAJOR_VERSION = "6" ]; then
        cd /cgroup/cpuset
    else
        cd /sys/fs/cgroup/cpuset
    fi
	mkdir -p pktg
	cd pktg
	 
	echo $PKTG_CPU_ID > cpuset.cpus
	echo 0 > cpuset.mems
	 
	for pid in `ps -ef | grep pktminerg | grep -v grep | awk '{print $2}'` ; do echo $pid > cgroup.procs; done
}

replay() {
	cd $SHELL_FOLDER
	echo "------------------------------------" >> stats.txt
	echo "`date`" >> stats.txt
	PPS=$1
    PCAP_FILE=$2
    LOOP=$3
	echo "$PPS"  >> stats.txt
	echo "$LOOP" >> stats.txt
	tcpreplay -i $REPLAY_ETH -p $PPS -l $LOOP $PCAP_FILE >> stats.txt &
}

run_pktg() {
	cd $SHELL_FOLDER
	echo "====================================" >> stats.txt
	echo "`date`" >> stats.txt
	NIC=$1
	echo "$NIC"  >> stats.txt
	pktminerg -i $NIC -r $GRE_RECV_IP -k 1 -p --cpu $PKTG_CPU_ID >> pktg.txt &
}

stats() {
	cd $SHELL_FOLDER
	for (( j=1; j<=10000000; j++ ))
	do
		echo "`ps aux  | grep pktminerg | grep -v grep`" >> stats.txt
		sleep 10
		COUNT=`ps aux | grep tcpreplay | grep -v grep | wc -l`
		if [ "$COUNT" -ge "1" ]
		then
			sleep 1
		else
			break
		fi
	done
    sleep 1
	echo "------------------------------------" >> stats.txt
}

pktg_test_case() {
	K=$1
    PCAPF=$2
    LOOPX=$3

	PPSA=$[ 10000 * $K ]
    LOOPN=$[ $LOOPX * $K ]
	echo "pps: $PPSA"
	echo "LOOPN: $LOOPN"
	
	run_pktg $REPLAY_ETH
	replay $PPSA $PCAPF $LOOPN
	stats

	killall pktminerg
}

main_test() {
    REPLAY_PCAP_FILE=$1
    REPLAY_LOOPX=$2

    for (( k=1; k<=50; k++ ))
    do
        pktg_test_case $k $REPLAY_PCAP_FILE $REPLAY_LOOPX
    done
}

if [ "$1" == "" ]
then
    echo "Usage:"
    echo "    sh test_agent.sh REPLAY_PCAP_FILE REPLAY_LOOPX"
    echo "        REPLAY_PCAP_FILE: input pcap for tcpreplay to send packets to NIC."
    echo "        REPLAY_LOOPX: use this coefficient to control tcpreplay duration."
    echo "Example:"
    echo "    sh test_agent.sh input.pcap 5"
else
    main_test $1 $2
fi

