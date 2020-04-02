#!/bin/sh

SHELL_FOLDER=`pwd`
MAJOR_VERSION=0
if [ -e /etc/centos-release ]; then
    MAJOR_VERSION=`rpm -q --queryformat '%{VERSION}' centos-release`
fi


prepare_iperf() {
	cd $SHELL_FOLDER
    if [ -e iperf_installed.txt ]; then
        echo "assume iperf installed"
    else
        yum -y install iperf psmisc
        echo 1 > iperf_installed.txt
    fi
}

cgroup_iperf() {
    if [ $MAJOR_VERSION = "6" ]; then
        cd /cgroup/cpuset
    else
        cd /sys/fs/cgroup/cpuset
    fi
	mkdir -p iperf
	cd iperf

	echo 0 > cpuset.cpus
	echo 0 > cpuset.mems

	for pid in `ps -ef | grep iperf | grep -v grep | awk '{print $2}'` ; do echo $pid > cgroup.procs; done
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
    IPERF_IP=$1
    IPERF_PORT=$2
	BPS=$3
    DURATION_S=$4
    STATS_TXT=stats-${IPERF_IP}-${IPERF_PORT}.txt

	echo "------------------------------------" >> stats.txt
	echo "`date`" >> stats.txt
	echo "Send to $IPERF_IP:$IPERF_PORT $BPS Mbps, $DURATION_S seconds"  >> stats.txt
    echo "iperf -c $IPERF_IP -p $IPERF_PORT -i 10 -t $DURATION_S -w 20K -m -b ${BPS}M -l 1406 -M 1406 -N" >> stats.txt

	echo "------------------------------------" >> $STATS_TXT
	echo "`date`" >> $STATS_TXT
	echo "Send to $IPERF_IP:$IPERF_PORT $BPS Mbps, $DURATION_S seconds"  >> $STATS_TXT
    echo "iperf -c $IPERF_IP -p $IPERF_PORT -i 10 -t $DURATION_S -w 20K -m -b ${BPS}M -l 1406 -M 1406 -N" >> $STATS_TXT

	#python /root/fake_iperf.py $DURATION_S &
	iperf -c $IPERF_IP -p $IPERF_PORT -i 60 -t $DURATION_S -w 20K -m -b ${BPS}M -l 1406 -M 1406 -N >> $STATS_TXT &
}

run_pktg() {
	cd $SHELL_FOLDER
	NIC=$1
    GRE_IP=$2
    GRE_KEYBIT=$3
    CPU_ID=$4
	echo "====================================" >> stats.txt
	echo "`date`" >> stats.txt
	echo "pktminerg -i $NIC -r $GRE_IP -k $GRE_KEYBIT -p --cpu $CPU_ID" >> stats.txt

	echo "====================================" >> pktg.txt 
	echo "`date`" >> pktg.txt
	echo "pktminerg -i $NIC -r $GRE_IP -k $GRE_KEYBIT -p --cpu $CPU_ID" >> pktg.txt
	pktminerg -i $NIC -r $GRE_IP -k $GRE_KEYBIT -p --cpu $CPU_ID -b 50 >> pktg.txt &
}

stats() {
	cd $SHELL_FOLDER
	for (( j=1; j<=10000000; j++ ))
	do
		echo "`ps aux  | grep pktminerg | grep -v grep`" >> stats.txt
		echo "`sar -n DEV 5 1 | grep Average.*eth | grep -v grep`" >> stats.txt
		sleep 10
		COUNT=`ps aux | grep iperf | grep -v grep | wc -l`
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
    IPERF_IP=$1
    IPERF_PORT=$2
	BPS=$3
    DURATION_S=$4
    REPLAY_ETH=$5
    GRE_RECV_IP=$6
    GRE_KEYBIT=$7
    PKTG_CPU_ID=$8

	echo "BPS: $BPS Mbps"
	
	echo "BPS: $BPS Mbps" >> pktg.txt
	run_pktg $REPLAY_ETH $GRE_RECV_IP $GRE_KEYBIT $PKTG_CPU_ID
    replay $IPERF_IP $IPERF_PORT $BPS $DURATION_S
    #replay 10.1.3.199 81 $BPS $DURATION_S
    #replay 10.1.3.199 81 $BPS $DURATION_S
	stats

	killall pktminerg
}

main_test() {
    IPERF_IP=$1
    IPERF_PORT=$2
    DURATION_S=$3
    REPLAY_ETH=$4
    GRE_RECV_IP=$5
    GRE_KEYBIT=$6
    PKTG_CPU_ID=$7

    for (( k=10; k<=100; k++ ))
    do
        pktg_test_case $1 $2 $k $3 $4 $5 $6 $7
    done
}



if [ "$#" -ne 7 ]; then
    echo "Usage:"
    echo "    sh test_pktg_perf.sh iperf_ip iperf_port duration_s replay_nic gre_recv_ip gre_keybit pktg_cpu_id"
    echo "        iperf_ip: iperf server IP to simulate network traffic"
    echo "        iperf_port: iperf server port to simulate network traffic"
    echo "        duration_s: duration seconds of each test case"
    echo "        replay_nic: tcpreplay target network interface(eth1, eth2...)."
    echo "        gre_recv_ip: remote ip to receive gre packet."
    echo "        grep_keybit: gre keybit"
    echo "        pktg_cpu_id: limit pktminerg to run on this cpu processor id (suggest to NOT use core 0)."
    echo "Example:"
    echo "    sh test_pktg_perf.sh 10.1.3.99 81 300 eth2 192.168.0.1 128 1"
else
    prepare_iperf
    echo "main_test"
    main_test $1 $2 $3 $4 $5 $6 $7
fi

