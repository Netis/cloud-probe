# Netis Packet Agent 0.3.0

[![Stable release](https://img.shields.io/badge/version-0.3.0-green.svg)](https://github.com/Netis/packet-agent/releases/tag/0.3.0)
[![Software License](https://img.shields.io/badge/license-BSD3-green.svg)](LICENSE)

Netis Packet Agent is an open source project to deal with such situation: it captures pakcets on *Machine A* but has to use them on *Machine B*. This case is very common when you try to monitor network traffic in the [LAN](https://en.wikipedia.org/wiki/Local_area_network) but the infrastructure is incapable, for example
- There is neither [TAP](https://en.wikipedia.org/wiki/Network_tap) nor [SPAN](http://docwiki.cisco.com/wiki/Internetworking_Terms:_Switched_Port_Analyzer_(SPAN)) device in a physical environment.
- The Virtual Switch [Flow Table](https://wiki.openstack.org/wiki/Ovs-flow-logic) does not support SPAN function in a virtualization environment.

Also, this project aims at developing a suite of low cost but high efficiency tools to survive the challenge above. *pktminerg* is the very first one, which makes you easily capture packets from an NIC interface, encapsulate them with GRE and send them to a remote machine for monitoring and analysis.

## Release Information

[Changes](CHANGES.md).

## Documentation

* [Installation](INSTALL.md) and [Usage](USAGE.md).
* [Build requirements and steps](BUILD.md).

## Support

Please report issues and suggestions via
[GitHub issues](https://github.com/Netis/packet-agent/issues).

## Contact us

* [E-mail us](mailto:developer@netis.com)

<br>
