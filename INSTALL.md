# Installation Instructions:

## CentOS6 or CentOS 7
1. Install the libpcap at first
```shell
yum install libpcap
```
2. Install the packet agent from RPM package. Please find the latest package form [Releases Page](https://github.com/Netis/packet-agent/releases).
```shell
wget https://github.com/Netis/packet-agent/releases/download/v0.3.0/netis-packet-agent-0.3.0.el6.x86_64.rpm
rpm -ivh netis-packet-agent-0.3.0.el6.x86_64.rpm
```
