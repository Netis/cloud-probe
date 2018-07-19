#!/bin/bash

NIC=$1
if [ ! $1 ]; then
    NIC='eth0'
fi

rm -rf gredump.pcap
rm -rf pktminer_dump.pcap

tcpreplay --pps=50 -i $NIC xml.pcap &

../bin/gredump -i $NIC -o gredump.pcap &
../bin/pktminerg -i $NIC -r 172.16.14.249 -c 1000 --dump

sleep 3

killall gredump
killall tcpreplay

../bin/pcapcompare pktminer_dump.pcap gredump.pcap


