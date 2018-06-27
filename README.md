# Netis Packet Agent 0.3.0

[![Stable release](https://img.shields.io/badge/version-0.3.0-green.svg)](https://github.com/Netis/packet-agent/releases/tag/0.3.0)
[![Software License](https://img.shields.io/badge/license-BSD3-green.svg)](LICENSE)

Netis Packet Agent is an open source project to deal with such situation: it captures pakcets on *Machine A* but has to use them on *Machine B*. This case is very common when you try to monitor network traffic in the [LAN](https://en.wikipedia.org/wiki/Local_area_network) but the infrastructure is incapable, for example
- There is neither [TAP](https://en.wikipedia.org/wiki/Network_tap) nor [SPAN](http://docwiki.cisco.com/wiki/Internetworking_Terms:_Switched_Port_Analyzer_(SPAN)) devince in a physical environment.
- The [Flow Table](https://wiki.openstack.org/wiki/Ovs-flow-logic) does not support SPAN function in a virtualization environment.

Ando also, this project aims to develop a suite of low cost but high efficiency tools to survive the challenge above. The *pktminerg* is the very first one, which makes you easily to capture packets from an NIC interface, encapsulate the packets with GRE, and then send them to a remote machine for monitoring and analysis.

## Release Information
Here are the latest [Changes](CHANGES.md).

## Documentation
* Netis Packet Agent [Install](INSTALL.md) and [Usage](USAGE.md).
* Netis Packet Agent [Build requirements and step](BUILD.md).

## Support
Please report issues and suggestions via
[GitHub issues](https://github.com/Netis/packet-agent/issues).

## Engineering team contacts
* [E-mail us.](mailto:developer@netis.com)
<br>
