#!/bin/bash

RECV_TAR_GZ=$1
MAJOR_VERSION=0
if [ -e /etc/centos-release ]; then
    MAJOR_VERSION=`rpm -q --queryformat '%{VERSION}' centos-release`
fi

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


install_recvzmq() {
    \cp -rf recvzmq_installer/recvzmq.py /usr/local/bin/recvzmq.py
    \cp -rf recvzmq_installer/backup_recvlog.sh /usr/local/bin/backup_recvlog.sh
    \cp -rf recvzmq_installer/recvd.sh /usr/local/etc/recvd.sh
    if [ $MAJOR_VERSION = "6" ]; then
        echo "sh /usr/local/etc/recvd.sh &" >> /etc/rc.d/rc.local
    elif [ $MAJOR_VERSION = "7" ]; then
        \cp -rf recvzmq_installer/recvzmq.service /etc/systemd/system/recvzmq.service
    fi

    echo "Install finished"
}


install_pyzmq() {
    if [ $MAJOR_VERSION = "6" ]; then
        rpm -ivh recvzmq_installer/pyzmq-el6/openpgm-5.1.118-3.el6.x86_64.rpm
        rpm -ivh recvzmq_installer/pyzmq-el6/zeromq3-3.2.5-1.el6.x86_64.rpm
        rpm -ivh recvzmq_installer/pyzmq-el6/python-zmq-14.3.1-1.el6.x86_64.rpm
    elif [ $MAJOR_VERSION = "7" ]; then
        rpm -ivh recvzmq_installer/pyzmq-el7/libsodium-1.0.18-1.el7.x86_64.rpm
        rpm -ivh recvzmq_installer/pyzmq-el7/openpgm-5.2.122-2.el7.x86_64.rpm
        rpm -ivh recvzmq_installer/pyzmq-el7/zeromq-4.1.4-6.el7.x86_64.rpm
        rpm -ivh recvzmq_installer/pyzmq-el7/python2-zmq-14.7.0-11.el7.x86_64.rpm
    else
        echo "Unsupported version: $MAJOR_VERSION"
        exit 1
    fi
}


mkdir -p recvzmq_installer
tar -xvf $RECV_TAR_GZ --strip-components 1 -C recvzmq_installer/

install_pyzmq
install_recvzmq

rm -rf recvzmq_installer

