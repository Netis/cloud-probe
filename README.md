# Netis Packet Agent 0.3.0

[![Stable release](https://img.shields.io/badge/version-0.3.0-green.svg)](https://github.com/Netis/packet-agent/releases/tag/0.3.0)
[![Software License](https://img.shields.io/badge/license-BSD3-green.svg)](LICENSE)

Netis Packet Agent aims at solving a problem where one wants to capture and utilize packets on two different machines. This is a very common case when you try to monitor network traffic in [LAN](https://en.wikipedia.org/wiki/Local_area_network) but the infrastructure is incapable. For example:

- There is neither [TAP](https://en.wikipedia.org/wiki/Network_tap) nor [SPAN](http://docwiki.cisco.com/wiki/Internetworking_Terms:_Switched_Port_Analyzer_(SPAN)) device in a physical environment.
- The [Flow Table](https://wiki.openstack.org/wiki/Ovs-flow-logic) does not support SPAN function in a virtualization environment.

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
