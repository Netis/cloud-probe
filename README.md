
English  ∙  [简体中文](README-zh-Hans.md) 

![packet agent's title](./img/title.jpg)
# Netis Packet Agent

[![Stable release](https://img.shields.io/badge/version-0.3.6-green.svg)](https://github.com/Netis/packet-agent/releases/tag/0.3.6)
[![Software License](https://img.shields.io/badge/license-BSD3-green.svg)](./LICENSE.md)

## What is Netis Packet Agent?
Netis Packet Agent is an open source project to deal with such situation: it captures packets on *Machine A* but has to use them on *Machine B*. This case is very common when you try to monitor network traffic in the [LAN](https://en.wikipedia.org/wiki/Local_area_network) but the infrastructure is incapable, for example
- There is neither [TAP](https://en.wikipedia.org/wiki/Network_tap) nor [SPAN](http://docwiki.cisco.com/wiki/Internetworking_Terms:_Switched_Port_Analyzer_(SPAN)) device in a physical environment.
- The Virtual Switch [Flow Table](https://wiki.openstack.org/wiki/Ovs-flow-logic) does not support SPAN function in a virtualization environment.

Also, this project aims at developing a suite of low cost but high efficiency tools to survive the challenge above.
- **pktminerg** is the very first one, which makes you easily capture packets from an NIC interface, encapsulate them with GRE and send them to a remote machine for monitoring and analysis.

![packet agent's pktminerg capture traffic flow via GRE/Cloud](./img/pktminerg.png)


With 3 utilities:
- **pcapcompare** is a utility for comparing 2 different pcap files.
- **gredump** is used for capturing GRE packet with filter, and save them to pcap file.
- **gredemo** is a demo app which is used to read packet from a pcap file and send them all to remote NIC. This can be only used when built from source code.
- **ProbeDaemon** is a new added module from v0.7.0, which is responsible for the management of the pktminerg process. It can pull and kill pktminerg process and set the parameters of pktminerg in the command line. This module should work with CPM (Cloud Probe Manager)，which provides a user interface to set the strategies of pktminerg and can also display the statistis reported from pktminerg in graphs. You can contact Netis for the further support of CPM, or you can also develop your CPM.


## Getting Started
### Installation

#### CentOS 6/7 and RedHat 7
1. Download and install the RPM package. Find the latest package from [Releases Page](https://github.com/Netis/packet-agent/releases).
```bash
wget https://github.com/Netis/packet-agent/releases/download/v0.7.0/netis-packet-agent-0.7.0.x86_64_centos.rpm
rpm -ivh netis-packet-agent-0.7.0.x86_64_centos.rpm
```

#### SUSE 12
1. Download and install the RPM package. Find the latest package from [Releases Page](https://github.com/Netis/packet-agent/releases).
```bash
wget https://github.com/Netis/packet-agent/releases/download/v0.7.0/netis-packet-agent-probe-0.7.0.x86_64_suse.rpm
rpm -ivh netis-packet-agent-probe-0.7.0.x86_64_suse.rpm
```


#### Ubuntu 18.04LTS
1. Download and install the DEB package. Find the latest package from [Releases Page](https://github.com/Netis/packet-agent/releases).
```bash
wget https://github.com/Netis/packet-agent/releases/download/v0.7.0/netis-packet-agent-0.7.0_amd64.deb
sudo dpkg -i netis-packet-agent-0.7.0_amd64.deb
```
Remarks: If it encounter a library dependency error when install from rpm, you should install boost_1_59_0 or later. If this also can't work, you can build and run from source.

Remarks: Now only support CentOS 6/7, RedHat 7, SUSE 12, Ubuntu 18.04 LTS.

#### Windows 7/8/10 x64
1. Download and Install [Winpcap](https://www.winpcap.org/install/bin/WinPcap_4_1_3.exe) of latest version. 
2. Download and Install [Microsoft Visual C++ Redistributable for Visual Studio 2017 x64](https://aka.ms/vs/15/release/vc_redist.x64.exe).
3. Extract pktminerg and other utilities from zip,  and run it in cmd in Administrator Mode.

<br>

### Usage
Remarks: Make sure the firewall allows GRE packets to be sent to the target.
https://lartc.org/howto/lartc.tunnel.gre.html provides a way to check firewall allows GRE packets to be sent.
```bash
# Capture packet from NIC "eth0", encapsulate with GRE header and send to 172.16.1.201
pktminerg "-i eth0 -r 172.16.1.201 -k 12"

# compare 2 pcap files
pcapcompare --lpcap /path/to/left_file.pcap --rpcap /path/to/right_file.pcap

# Capture packet from NIC "eth0" and save them to gredump_output.pcap
gredump -i eth0 -o /path/to/gredump_output.pcap

# Capture packets from NIC "eth0", forward to 172.16.1.201 with GRE encapsulated and capture packets from "eth1", forward to 10.1.2.123 with vni encapsulated
pktminerg "-i eth0 -r 172.16.1.201 -k 12" "-i eth1 -r 10.1.2.123 -n 12"
```
![packet agent's pktminerg : network capture use case](./img/use_case.png)

For more information on using these tools, please refer to this [document](./USAGE.md).

For docker usage, please refer to this [document](./DOCKER.md).

### Build from source.
You can also clone source from Github and build Netis Packet Agent in local, then check"/path/to/packet-agent/bin" to find all binary.
<br/>
For build precondition and steps, please refer to this [document](./BUILD.md).

## Documentation / Useful link
* [Build requirements and steps](./BUILD.md).
* [Release Information / Roadmap](./CHANGES.md).

## Contributing
Fork the project and send pull requests. We welcome pull requests from members of all open source community.

## License
Copyright (c) 2018 - 2020 Netis.<br/>
The content of this repository bound by the following licenses:
- The computer software is licensed under the [BSD-3-Clause](./LICENSE.md).

## Contact info
* You can E-mail to [developer@netis.com](mailto:developer@netis.com).
* You can also report issues and suggestions via [GitHub issues](https://github.com/Netis/packet-agent/issues).

<br/>
