#!/bin/sh

export LD_LIBRARY_PATH=/usr/local/lib64:$LD_LIBRARY_PATH
./cpagent --tasks tasks.json --enable-dpdk-dumpcap --cpu-set 1,2 --unix-socket cpagent.socket
