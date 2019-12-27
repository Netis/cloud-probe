
# Protocol ERSPAN Type III Plugin 0.1.0

[![Stable release](https://img.shields.io/badge/version-0.1.0-green.svg)](https://github.com/Netis/packet-agent/releases/tag/0.4.0)
[![Software License](https://img.shields.io/badge/license-BSD3-green.svg)](./LICENSE.md)


## Introduce
Protocol ERSPAN Type III Plugin(or extension) is a dynamic library for port mirror export tunnel protocol along with Netis Packet Agent. 

## Getting Started
### Installation
```bash
cd ./packet-agent/ext/proto_erspan_type3
cmake .
make -j 4
# Then the libproto_erspan_type3.so binary will be generated at "./packet-agent/bin/".
```


### Usage Explanation and Example
```bash
# The port mirror extension's configuration field explanations:
# ext_file_path(mandatory): .so file with absolute path, or relative path from pwd. This field is mandatory.
# ext_params(mandatory): the configuration for particular extension(plugin or dynamic library). Any field in ext_params can be absent for default config(false / 0).
#     remoteips(mandatory): the list of remote ips. 
#     bind_device/pmtudisc_option: export socket options
#     use_default_header: Use default value for all field. if set to true, another field in ext_params has no effect.
#     enable_spanid/spani/enable_sequence/sequence_begin/enable_timestamp/timestamp_type/enable_key/key/vni: as name said.


# Examples: 
#  - these examples list all available field.

# proto_erspan_type3 
JSON_STR=$(cat << EOF
{
    "ext_file_path": "libproto_erspan_type3.so",
    "ext_params": {
        "remoteips": [
            "10.1.1.37",
            "10.1.1.38"
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
./pktminerg -i eth0 --proto-config "${JSON_STR}"

```
## Platform
Now only support Linux platform.

## Contributing
Fork the project and send pull requests. We welcome pull requests from members of all open source community.

## License
Copyright (c) 2019 - 2020 Netis.<br/>
- This plugin source code is licensed under the [BSD-3-Clause](./LICENSE.md).

## Contact info
* You can E-mail to [developer@netis.com](mailto:developer@netis.com).
* You can also report issues and suggestions via [GitHub issues](https://github.com/Netis/packet-agent/issues).

<br/>
