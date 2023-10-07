#!/bin/bash

NIC=$1
if [ ! $1 ]; then
    NIC='eth0'
fi

../bin/pktminerg "-i $NIC -r 172.16.14.249 --control 5556" &
sleep 10
python2.7 test_control_plane_client.py
sleep 10
killall pktminerg

