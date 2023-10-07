#!/bin/bash
probedaemon --config /etc/agent-daemon.conf >/dev/null &
echo "$!" > /var/run/probe-daemon/probe-daemon.pid
