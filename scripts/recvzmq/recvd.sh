#!/bin/bash
python /usr/local/bin/recvzmq.py -z 82 -s 15 -a 4 -t /opt/pcap_cache/nic0/%Y%m%d%H%M%S 1>>/opt/bpc/var/log/recvzmq.log 2>>/opt/bpc/var/log/recvzmq.err &
RECV_PID=$! 

rm -rf /var/run/recvzmq/recvzmq.pid
sh /usr/local/bin/backup_recvlog.sh /opt/bpc/var/log/recvzmq.log &
BACKUP_PID=$!

echo "$RECV_PID" > /var/run/recvzmq/recvzmq.pid
echo "$BACKUP_PID" >> /var/run/recvzmq/recvzmq.pid

