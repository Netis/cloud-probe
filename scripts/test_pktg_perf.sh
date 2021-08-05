#!/bin/sh

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
    CPU_IDS=$1
    if [ $MAJOR_VERSION = "6" ]; then
        cd /cgroup/cpuset
    else
        cd /sys/fs/cgroup/cpuset
    fi
	mkdir -p pktg
	cd pktg
	 
	echo $CPU_IDS > cpuset.cpus
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
    REPLAY_NIC=$4
	echo "$PPS"  >> stats.txt
	echo "$LOOP" >> stats.txt
	tcpreplay -i $REPLAY_NIC -p $PPS -l $LOOP $PCAP_FILE >> stats.txt &
}

run_pktg() {
	cd $SHELL_FOLDER
	echo "====================================" >> stats.txt
	echo "`date`" >> stats.txt
	NIC=$1
    GRE_IP=$2
    CPU_ID=$3
	echo "$NIC"  >> stats.txt
	pktminerg -i $NIC -r $GRE_IP -k 1 -p --cpu $CPU_ID >> pktg.txt &
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
    REPLAY_ETH=$4
    GRE_RECV_IP=$5
    PKTG_CPU_ID=$6

	PPSA=$[ 10000 * $K ]
    LOOPN=$[ $LOOPX * $K ]
	echo "pps: $PPSA"
	echo "LOOPN: $LOOPN"
	
	run_pktg $REPLAY_ETH $GRE_RECV_IP $PKTG_CPU_ID
	replay $PPSA $PCAPF $LOOPN $REPLAY_ETH
	stats

	killall pktminerg
}

main_test() {
    REPLAY_PCAP_FILE=$1
    REPLAY_LOOPX=$2

    for (( k=1; k<=100; k++ ))
    do
        pktg_test_case $k $REPLAY_PCAP_FILE $REPLAY_LOOPX $3 $4 $5
    done
}

if [ "$#" -ne 5 ]; then
    echo "Usage:"
    echo "    sh test_pktg_perf.sh pcap_file loopx replay_nic gre_recv_ip pktg_cpu_id"
    echo "        pcap_file: input pcap for tcpreplay to send packets to NIC."
    echo "        loopx: use this coefficient to control tcpreplay duration."
    echo "        replay_nic: tcpreplay target network interface(eth1, eth2...)."
    echo "        gre_recv_ip: remote ip to receive gre packet."
    echo "        pktg_cpu_id: limit pktminerg to run on this cpu processor id (suggest to NOT use core 0)."
    echo "Example:"
    echo "    sh test_pktg_perf.sh input.pcap 5 eth2 192.168.0.1 1"
else
    main_test $1 $2 $3 $4 $5
fi

