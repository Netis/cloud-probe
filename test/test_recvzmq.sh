#!/bin/bash

rm -rf ./nic1/*

python ../scripts/recvzmq/recvzmq.py -z 5555 -t ./nic1/%Y%m%d%H%M%S -s 15 -a 1 &
../bin/pktminerg -f xml.pcap -r 127.0.0.1 -k 15 -z 5555 &
sleep 20

tshark -r ./nic1/20130327104800_1_0.pcap | grep -v :00_00: > ./nic1/xmltshark.txt
sed -i 's/^ *[0-9]\+ *[0-9.]\+ //g' ./nic1/xmltshark.txt

killall pktminerg
ps -ef | grep python.*recvzmq.py | grep -v grep | awk '{print $2}' | xargs kill

diff xmltshark_baseline.txt ./nic1/xmltshark.txt
if [ $? -eq 0 ]; then
    echo "test 1 ok"
else
    echo "test 1 failed"
    exit 1
fi




rm -rf ./nic2/*
python ../scripts/recvzmq/recvzmq.py -z 5555 -t ./nic2/%Y%m%d%H%M%S -s 15 -a 2 &
../bin/pktminerg -f xml.pcap -r 127.0.0.1 -k 3 -z 5555 &
sleep 20

mergecap -w mergedgre.pcap ./nic2/*.pcap
mv mergedgre.pcap ./nic2/
tshark -r ./nic2/mergedgre.pcap | grep -v :00_00: > ./nic2/xmltshark2.txt
sed -i 's/^ *[0-9]\+ *[0-9.]\+ //g' ./nic2/xmltshark2.txt

killall pktminerg
ps -ef | grep python.*recvzmq.py | grep -v grep | awk '{print $2}' | xargs kill

diff xmltshark_baseline.txt ./nic2/xmltshark2.txt
if [ $? -eq 0 ]; then
    echo "test 2 ok"
else
    echo "test 2 failed"
    exit 1
fi

