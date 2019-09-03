# Installation instructions:

## CentOS 6/7 and RedHat 7

1. Install libpcap and wget

```shell
yum install libpcap wget
```
Note: The default libpcap with TPACKET_V3 enabled has some performance issue. If performance is critical, you can remove libpcap and reinstall libpcap-1.8.1-6.fc27.x86_64.rpm or newer version which drops the TPACKET_V3 patch: http://rpm.pbone.net/index.php3/stat/22/idpl/50238989/com/changelog.html

2. Download and install the RPM package. Find the latest package from [Releases Page](https://github.com/Netis/packet-agent/releases).

```shell
wget https://github.com/Netis/packet-agent/releases/download/v0.3.3/netis-packet-agent-0.3.4.el6.x86_64.rpm
rpm -ivh netis-packet-agent-0.3.4.el6.x86_64.rpm
```

## SUSE 12

1. Download and install the RPM package. Find the latest package from [Releases Page](https://github.com/Netis/packet-agent/releases).

```shell
wget https://github.com/Netis/packet-agent/releases/download/v0.3.3/netis-packet-agent-0.3.4.el6.x86_64.rpm
rpm -ivh netis-packet-agent-0.3.4.el6.x86_64.rpm
```
