#!/bin/bash

RECV_TAR_GZ=$1

Usage() {
    echo "Usage:"
    echo "      sh recvzmq_installer.sh <recvzmq-tar-gz>"
    echo "<recvzmq-tar-gz>:"
    echo "      path to recvzmq.tar.gz which include recvzmq.py, recvzmq.service etc..."
    echo "Example:"
    echo "      sh recvzmq_installer.sh /path/to/recvzmq.tar.gz"
}

if [[ -z "$RECV_TAR_GZ" ]]; then
    Usage
    exit 1
fi

yum -y install python-zmq

mkdir -p recvzmq_installer
tar -xvf $RECV_TAR_GZ --strip-components 1 -C recvzmq_installer/

\cp -rf recvzmq_installer/recvzmq.py /usr/local/bin/recvzmq.py
\cp -rf recvzmq_installer/backup_recvlog.sh /usr/local/bin/backup_recvlog.sh
\cp -rf recvzmq_installer/recvd.sh /usr/local/etc/recvd.sh
\cp -rf recvzmq_installer/recvzmq.service /etc/systemd/system/recvzmq.service

rm -rf recvzmq_installer

echo "Install finished"

