#!/bin/sh

./build/cpagent --tasks tasks.json --enable-dpdk-dumpcap --cpu-set 1,2 --unix-socket cpagent.socket
