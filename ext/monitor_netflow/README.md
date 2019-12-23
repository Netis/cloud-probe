
# Netflow Monitor Plugin 0.1.0

[![Stable release](https://img.shields.io/badge/version-0.0.1-green.svg)](https://github.com/Netis/packet-agent/releases/tag/0.3.5)
[![Software License](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](./COPYING)


## Introduce
Netflow Monitor Plugin( or extension) is a dynamic library for interface traffic monitor along with Netis Packet Agent. It based on fprobe and can support Netflow V1/5/7 protocols.

## Getting Started
### Installation
```bash
cd ./packet-agent/ext/monitor_netflow
cmake .
make -j 4
# Then the libmonitor_netflow.so binary will be generated at "./packet-agent/bin/".
```


### Usage Explanation and Example
```bash
# The traffic monitor extension's configuration field explanations:
# ext_file_path(mandatory): .so file with absolute path, or relative path from pwd. This field is mandatory.
# ext_params(mandatory): the configuration for particular extension(plugin or dynamic library). Any field in ext_params can be absent for default config(false / 0).
#     collectors_ipport(mandatory): the list of collectors. 
#         ip: collector ip.
#         port: netflow packet send port.
#     netflow_version: (optional, default=5) Netflow protocol version. Now only support v1/5/7.


# Examples: 
#  - these examples list all available field.

# monitor_netflow 
# combination of 2 type extention
JSON_STR=$(cat << EOF
{
    "ext_file_path": "libproto_erspan_type3.so",
    "ext_params": {
        "remoteips": [
            "10.1.1.37"
        ],
        "bind_device": "eno16777984",
        "pmtudisc_option": "dont",
        "use_default_header": false,
        "enable_spanid": true,
        "spanid": 1020,
        "enable_sequence": true,
        "sequence_begin": 10000,
        "enable_timestamp": true,
        "timestamp_type": 0,
        "enable_security_grp_tag": true,
        "security_grp_tag": 32768,
        "enable_hw_id": true,
        "hw_id": 31        
    }
}
EOF
)

MON_STR=$(cat << EOF
{
    "ext_file_path": "libmonitor_netflow.so",
    "ext_params": {
        "collectors_ipport": [
            {
                "ip": "10.1.1.37",
                "port": 2055
            },
            {
                "ip": "10.1.1.38",
                "port": 2055
            }
        ],
        "netflow_version": 5
    }
}
EOF
)
./pktminerg -i eth0 --proto-config "${JSON_STR}" --monitor-config "${MON_STR}"

```
## Platform
Now only support Linux platform.

## Contributing
Fork the project and send pull requests. We welcome pull requests from members of all open source community.

## License
Copyright (c) 2019 Netis.<br/>
- This plugin source code is licensed under the [GPL v2](./COPYING).

## Contact info
* You can E-mail to [developer@netis.com](mailto:developer@netis.com).
* You can also report issues and suggestions via [GitHub issues](https://github.com/Netis/packet-agent/issues).

<br/>
