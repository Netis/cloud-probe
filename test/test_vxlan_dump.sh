#!/bin/bash

NIC=$1
if [ ! $1 ]; then
    NIC='eth0'
fi

COMPARE=compare
if [ "$2" == "nocompare" ]; then
    COMPARE=nocompare
fi

rm -rf udpvxlan_dump.pcap
rm -rf pktminer_dump.pcap

../bin/vxlandump -n 1314 -o vxlan_dump.pcap &
../bin/pktminerg -i $NIC -r 0.0.0.0 --dump -n 1314 &
tcpreplay -i $NIC -M 10 -l 1 xml.pcap &

sleep 30

killall tcpreplay
killall pktminerg
killall vxlandump

if [ "$COMPARE" == "compare" ]; then
    ../bin/pcapcompare pktminer_dump.pcap udpvxlan_dump.pcap
fi


