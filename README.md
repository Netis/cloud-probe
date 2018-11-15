
English  ∙  [简体中文](README-zh-Hans.md) 

![title](./img/title.jpg)
# Netis Packet Agent 0.3.1

[![Stable release](https://img.shields.io/badge/version-0.3.1-green.svg)](https://github.com/Netis/packet-agent/releases/tag/0.3.1)
[![Software License](https://img.shields.io/badge/license-BSD3-green.svg)](./LICENSE.md)

## What is Netis Packet Agent?
Netis Packet Agent is an open source project to deal with such situation: it captures pakcets on *Machine A* but has to use them on *Machine B*. This case is very common when you try to monitor network traffic in the [LAN](https://en.wikipedia.org/wiki/Local_area_network) but the infrastructure is incapable, for example
- There is neither [TAP](https://en.wikipedia.org/wiki/Network_tap) nor [SPAN](http://docwiki.cisco.com/wiki/Internetworking_Terms:_Switched_Port_Analyzer_(SPAN)) device in a physical environment.
- The Virtual Switch [Flow Table](https://wiki.openstack.org/wiki/Ovs-flow-logic) does not support SPAN function in a virtualization environment.

Also, this project aims at developing a suite of low cost but high efficiency tools to survive the challenge above.
- **pktminerg** is the very first one, which makes you easily capture packets from an NIC interface, encapsulate them with GRE and send them to a remote machine for monitoring and analysis.

![chart](./img/pktminerg.png)

With 3 utilities:
- **pcapcompare** is a utility for comparing 2 different pcap files.
- **gredump** is used for capturing GRE packet with filter, and save them to pcap file.
- **gredemo** is a demo app which is used to read packet from a pcap file and send them all to remote NIC. This can be only used when built from source code.


## Getting Started
### Installation

#### CentOS 6/7 and RedHat 7
1. Install libpcap and wget
```bash
yum install libpcap wget
```

2. Download and install the RPM package. Find the latest package from [Releases Page](https://github.com/Netis/packet-agent/releases).
```bash
wget https://github.com/Netis/packet-agent/releases/download/v0.3.1/netis-packet-agent-0.3.1.el6.x86_64.rpm
rpm -ivh netis-packet-agent-0.3.1.el6.x86_64.rpm
```

#### SUSE 12
1. Download and install the RPM package. Find the latest package from [Releases Page](https://github.com/Netis/packet-agent/releases).
```bash
wget https://github.com/Netis/packet-agent/releases/download/v0.3.1/netis-packet-agent-0.3.1.el6.x86_64.rpm
rpm -ivh netis-packet-agent-0.3.1.el6.x86_64.rpm
```
Remarks: If it encounter a library dependency error when install from rpm, you should install boost_1_59_0 or later. If this also can't work, you can build and run from source.

Remarks: Now only support CentOS 6/7, RedHat 7, SUSE 12.

### Usage
```bash
# Capture packet from NIC "eth0", encapsulate with GRE header and send to 172.16.1.201
pktminerg -i eth0 -r 172.16.1.201

# Specify cpu 1 for this program with high priority to avoid thread switch cost.
pktminerg -i eth0 -r 172.16.1.201 --cpu 1 -p

# compare 2 pcap files
pcapcompare --lpcap /path/to/left_file.pcap --rpcap /path/to/right_file.pcap

# Capture packet from NIC "eth0" and save them to gredump_output.pcap
gredump -i eth0 -o /path/to/gredump_output.pcap
```
![pktminer_use_case](./img/use_case.png)

For more information on using these tools, please refer to this [document](./USAGE.md).

### Build from source.
You can also clone source from Github and build Netis Packet Agent in local, then check"/path/to/packet-agent/bin" to find all binary.
<br/>
For build precondition and steps, please refer to this [document](./BUILD.md).

## Documentation / Useful link
* [Installation](./INSTALL.md) and [Usage](./USAGE.md).
* [Build requirements and steps](./BUILD.md).
* [Release Information / Roadmap](./CHANGES.md).

## Contributing
Fork the project and send pull requests. We welcome pull requests from members of all open source community.

## License
Copyright (c) 2018 Netis.<br/>
The content of this repository bound by the following licenses:
- The computer software is licensed under the [BSD-3-Clause](./LICENSE.md).

## Contact info
* You can E-mail to [developer@netis.com](mailto:developer@netis.com).
* You can also report issues and suggestions via [GitHub issues](https://github.com/Netis/packet-agent/issues).

<br/>
