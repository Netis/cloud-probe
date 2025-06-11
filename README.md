
English  ∙  [简体中文](README-zh-Hans.md)

# Netis Cloud Probe

[![Stable release](https://img.shields.io/badge/version-0.3.6-green.svg)](https://github.com/Netis/cloud-probe/releases/tag/0.3.6)
[![Software License](https://img.shields.io/badge/license-BSD3-green.svg)](./LICENSE.md)

## What is Netis Cloud Probe?
Netis Cloud probe (formerly known as Packet Agent) is an open-source project used to solve the following problem: capturing packets on device A and then using them for analysis on device B. In many cases, when you want to monitor network traffic but there are no available devices, for example:
- There are no [TAP](https://en.wikipedia.org/wiki/Network_tap) and [SPAN](http://docwiki.cisco.com/wiki/Internetworking_Terms:_Switched_Port_Analyzer_(SPAN)) devices in the physical environment.
- In the virtual environment, the Virtual Switch [Flow Table](https://wiki.openstack.org/wiki/Ovs-flow-logic) does not support the SPAN function.

Therefore, this project provides a set of low-overhead but high-performance packet capture tools to deal with the above difficulties.
- **cpworker** This tool can easily capture packets on the network card and send the packets to a remote device through different output methods, enabling packet monitoring and analysis.

![capture traffic flow via GRE/Cloud](./overview.png)

In addition, there are other tools:
- **cpdaemon** is the management program of cpworker. It can start and stop cpworker. This module needs to work with CPM (Cloud Probe Mananger). CPM provides a user interface, which can configure the policies of cpworker and graphically display the statistical data reported by cpdaemon. You can contact Netis for further support regarding CPM, or you can develop your own CPM.

## Quick Start

### Capture packets via libpcap, encapsulate them with a GRE header, and send them to a remote device
Note: Please ensure that the firewall allows sending GRE packets to the target.
https://lartc.org/howto/lartc.tunnel.gre.html provides a method to verify whether sending GRE packets to the target is allowed.

Create a new configuration file, for example: `libpcap_gre.json`
```json
{
    "log_level": "INFO",
    "control": {
        "type": "unix",
        "unix": {
            "path": "/var/run/cloud-probe/cpworker.sock"
        }
    },
    "tasks": [
        {
            "req_pattern": {
                "type": "auto"
            },
            "capturer": {
                "type": "libpcap",
                "libpcap": {
                    "interface": "eth0",
                    "snaplen": 2048,
                    "buffer_size_mb": 256
                }
            },
            "outputs": [
                {
                    "type": "gre",
                    "gre": {
                        "host": "172.16.1.201",
                        "bind_device": "eth1"
                    }
                }
            ]
        }
    ]
}
```

run command:

```bash
cpworker -c libpcap_gre.json
```

## Forwarding rate comparison test
| Version | Output Type | Forwarding BPS | Forwarding PPS | CPU Utilization | Version | Forwarding BPS | Forwarding PPS | CPU Utilization | Forwarding BPS Increase% | Forwarding PPS Increase% | CPU Utilization Increase% |
| ------- | ----------- | -------------- | -------------- | --------------- | ------- | -------------- | -------------- | --------------- | ------------------------- | ------------------------- | ------------------------- |
| 0.8.7   | ZMQ         | 1560Mbps       | 241K           | 110%            | 0.9.0   | 2680Mbps       | 409K           | 49%             | +71.8%                    | +69.7%                    | -55.4%                    |
|         | GRE         | 786Mbps        | 120K           | 90%             |         | 883Mbps        | 135K           | 58%             | +12.3%                    | +12.5%                    | -35.5%                    |
|         | VXLAN       | 820Mbps        | 125K           | 96%             |         | 883Mbps        | 135K           | 52%             | +7.7%                     | +8%                       | -45.8%                    |


## Documentation / Useful link
* [INSTALL](./docs/INSTALL.md)
* [USAGE](./docs/USAGE-CPWORKER.md)
* [Build requirements and steps](./docs/BUILD.md)

## Contributing
Fork the project and send pull requests. We welcome pull requests from members of all open source community.

## Support
This project is provided to teams with development capabilities, and there is no official commitment to provide support. For details see [SUPPORT.md](./SUPPORT.md)。

## License
Copyright (c) 2018 - 2020 Netis.

The content of this repository bound by the following licenses:
- The computer software is licensed under the [BSD-3-Clause](./LICENSE.md).

## Contact info
* You can E-mail to [developer@netis.com](mailto:developer@netis.com).
* You can also report issues and suggestions via [GitHub issues](https://github.com/Netis/cloud-probe/issues).

## Issue template
* if you have any issue to report, please use the issue template provided([issue_report_template_English.md](.github/ISSUE_TEMPLATE/issue_report_template_English.md)).
