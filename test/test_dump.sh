#!/bin/bash

rm -rf gredump.pcap
rm -rf pktminer_dump.pcap

tcpreplay --pps=50 -i eth0 xml.pcap &

../bin/gredump -i eth0 -o gredump.pcap &
../bin/pktminerg -i eth0 -r 172.16.14.249 -c 1000 --dump

sleep 3

killall gredump
killall tcpreplay

../bin/pcapcompare pktminer_dump.pcap gredump.pcap


