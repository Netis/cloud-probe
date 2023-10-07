# Installation instructions:

## CentOS 6/7 and RedHat 7

1. Install libpcap and wget

```shell
yum install libpcap wget
```
Note: The default libpcap with TPACKET_V3 enabled has some performance issue. If performance is critical, you can remove libpcap and reinstall libpcap-1.8.1-6.fc27.x86_64.rpm or newer version which drops the TPACKET_V3 patch: http://rpm.pbone.net/index.php3/stat/22/idpl/50238989/com/changelog.html

2. Download and install the RPM package. Find the latest package from [Releases Page](https://github.com/Netis/packet-agent/releases).

```shell
wget https://github.com/Netis/packet-agent/releases/download/v0.3.6/netis-packet-agent-0.3.6.el6.x86_64.rpm
rpm -ivh netis-packet-agent-0.3.6.el6.x86_64.rpm
```


## Ubuntu 18.04LTS

1. Install libpcap and wget
```bash
sudo apt-get install libpcap-dev wget
```

2. Download and install the DEB package. Find the latest package from [Releases Page](https://github.com/Netis/packet-agent/releases).
```bash
wget https://github.com/Netis/packet-agent/releases/download/v0.3.6/netis-packet-agent-0.3.6_amd64.deb
sudo dpkg -i netis-packet-agent-0.3.6_amd64.deb
```

3. If libpcap.so.1 not found when running pktminerg, create softlink for libpcap.so.1 in suitable directory.
```bash
whereis libpcap.so
cd /path/to/libpcap.so
ln -s libpcap.so.x.y.z libpcap.so.1
```


## SUSE 12

1. Install libpcap and wget

```shell
yum install libpcap wget
```

2. Download and install the RPM package. Find the latest package from [Releases Page](https://github.com/Netis/packet-agent/releases).

```shell
wget https://github.com/Netis/packet-agent/releases/download/v0.3.6/netis-packet-agent-0.3.6.el6.x86_64.rpm
rpm -ivh netis-packet-agent-0.3.6.el6.x86_64.rpm
```


## Windows 7/8/10 x64

1. Download and Install [Winpcap](https://www.winpcap.org/install/bin/WinPcap_4_1_3.exe) of latest version. 
2. Download and Install [Microsoft Visual C++ Redistributable for Visual Studio 2017 x64](https://aka.ms/vs/15/release/vc_redist.x64.exe).
3. Download and ZIP package. Find the latest package from [Releases Page](https://github.com/Netis/packet-agent/releases).
4. Extract pktminerg and other utilities from zip,  and run it in cmd in Administrator Mode.

Note: On Windows platform, you must use NIC's NT Device Name with format "\Device\NPF_{UUID}" as interface param. You can get it with following command: 
```
    C:\> getmac /fo csv /v 
    "Connection Name","Network Adapter","Physical Address","Transport Name" 
    "Ethernet","Intel(R) Ethernet Connection (4) I219-V","8C-16-45-6B-53-B5","\Device\Tcpip_{4C25EA92-09DF-4FD3-A8B3-1B68E57443E2}" 
``` 
Take last field(Transport Name) and replace "Tcpip_" with "NPF_" as follow, then you can get interface param of Windows. 
```
    \Device\NPF_{4C25EA92-09DF-4FD3-A8B3-1B68E57443E2} 
``` 
Use example:
```
    C:\> pktminerg -i \Device\NPF_{4C25EA92-09DF-4FD3-A8B3-1B68E57443E2} -r 172.24.103.201 
    C:\> gredump -i \Device\NPF_{4C25EA92-09DF-4FD3-A8B3-1B68E57443E2} -o capture.pcap
```

