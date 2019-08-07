#!/bin/bash
pktminerg -i eth0 -r 127.0.0.1 >/dev/null &
echo "$!" > /var/run/packet-agent/pktminerg.pid
