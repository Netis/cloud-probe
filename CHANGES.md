# Change list

The list of the most significant changes made in Netis Packet Agent over time.


## Netis Packet Agent 0.4.0

### Features
* Support following plugin for export tunnel protocol and monitor protocol:
** proto_gre
** proto_erspan_type1
** proto_erspan_type2
** proto_erspan_type3
** proto_vxlan
** monitor_netflow

## Netis Packet Agent 0.3.5

### Features
* Support option check for '--nofilter' option invalid usage. In version 0.3.5 or later, pktminerg will exit directly in the following cases:
    - if you enable '--nofilter' option without specifying gre bind device(-B) in online mode.
    - if you enable '--nofilter' option and gre bind device(-B) is same as packet captured interface(-i) in online mode. 

## Netis Packet Agent 0.3.4

### Features
* Support MTU discovery strategy.

## Netis Packet Agent 0.3.3

### Features
* Support send GRE packets to multi-remoteip
* Support send GRE packets from binded device (network interface).
* Support systemd

## Netis Packet Agent 0.3.2

### Features
* Add Windows support

## Netis Packet Agent 0.3.1

### Bug Fixes
* Remove rpm install boost library dependencies.


## Netis Packet Agent 0.3.0

Initial release.

### Features
* Capture packets from an NIC interface, encapsulate them with GRE and send them to a remote machine for monitoring and analysis. All with ease.

### Documentation:

* For first use: [README](README.md), [INSTALL](INSTALL.md), [USAGE](USAGE.md), [BUILD](BUILD.md), [CHANGES](CHANGES.md), [LICENSE](LICENSE.md).

### Packaging:

* Package for Linux installs EM64T bits.
* Linux installer allows root, RPM installs.
