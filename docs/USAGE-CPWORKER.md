# cpworker User Manual

## Overview
cpworker is a network packet capture tool built on libpcap, supporting multiple output methods and intelligent traffic control.

## Configuration Template
```json
{
    "cpu_affinity": 1,
    "log_level": "INFO",
    "control": {
        "type": "unix",
        "unix": {
            "path": "/var/run/cloud-probe/cpworker.sock"
        }
    },
    "tasks": [
        {
            "interface": "eth0",
            "snaplen": 2048,
            "netns": "/proc/1432897/ns/net",
            "req_pattern": {
                "type": "custom",
                "custom": {
                    "pattern": "host nic.eth0 and port 8011"
                }
            },
            "capturer": {
                "type": "libpcap",
                "libpcap": {
                    "bpf": "host nic.eth0",
                    "buffer_size_mb": 256,
                    "timeout_ms": 3
                }
            },
            "outputs": [
                {
                    "type": "file",
                    "rate_limit_mbps": 10,
                    "slice": 2048,
                    "vxlan": {
                        "host": "10.1.2.3",
                        "port": 4789,
                        "capture_time": false,
                        "vni1": 1,
                        "vni2": 33,
                        "bind_device": "eth3",
                        "pmtudisc": "want"
                    },
                    "gre": {
                        "host": "10.1.2.3",
                        "service_tag": 34,
                        "bind_device": "eth3",
                        "pmtudisc": "want"
                    },
                    "zmq": {
                        "host": "10.1.2.3",
                        "port": 1234,
                        "hwm": 1000,
                        "service_tag": 3
                    },
                    "file": {
                        "name": "$PCAP_STORE_PATH/test.pcap"
                    },
                    "rotating_file": {
                        "file_root": "$PCAP_STORE_PATH",
                        "max_file_interval": 60
                    }
                }
            ]
        }
    ]
}
```

For more configuration examples, see: [examples](../cpworker/examples)


## Top-level Parameters
| Parameter          | Type     | Default | Description |
|--------------------|----------|---------|-------------|
| cpu_affinity       | int      | -       | Set CPU affinity |
| log_level          | string   | INFO    | Log level (DEBUG, INFO, WARN, ERROR) |
| control            | object   | -       | Control plane communication interface |
| control.type       | string   | -       | Control interface type (currently supports: unix) |
| control.unix.path  | string   | -       | Unix socket file path |

## Task Parameters
| Parameter                     | Type     | Default | Description |
|-------------------------------|----------|---------|-------------|
| interface                     | string   | -       | Capture NIC name (required) |
| snaplen                       | int      | 2048    | Packet truncation length |
| netns                         | string   | -       | Network namespace of the NIC |
| req_pattern                   | object   | -       | Packet direction detection |
| req_pattern.type              | string   | -       | Direction mode (auto/custom). NONCHECK if unconfigured |
| req_pattern.custom.pattern    | string   | -       | Pattern where `nic.eth0` will be replaced with eth0's IP |
| capturer                      | object   | -       | Packet capture settings |
| capturer.type                 | string   | -       | Capture type (currently supports: libpcap) |

## capturer.libpcap Parameters
| Parameter        | Type     | Default | Description |
|------------------|----------|---------|-------------|
| bpf              | string   | -       | BPF filter |
| buffer_size_mb   | int      | -       | Buffer size (MB) |
| timeout_ms       | int      | -       | Timeout (milliseconds) |

## Output Parameters
| Parameter         | Type     | Default | Description |
|-------------------|----------|---------|-------------|
| type              | string   | -       | Output type |
| rate_limit_mbps   | int      | -       | Max output rate (Mbps), unlimited by default |
| slice             | int      | -       | Packet truncation size (no truncation by default) |

## output.gre Parameters
| Parameter         | Type     | Default | Description |
|-------------------|----------|---------|-------------|
| host              | string   | -       | Destination IP |
| bind_device       | string   | -       | Bind interface (default: any) |
| pmtudisc          | string   | -       | MTU discovery mode (do/dont/want) |
| service_tag       | int      | -       | Service tag |

## output.vxlan Parameters
| Parameter         | Type     | Default | Description |
|-------------------|----------|---------|-------------|
| host              | string   | -       | Destination IP |
| port              | int      | -       | Destination port |
| capture_time      | bool     | -       | Add capture timestamp |
| vni1              | int      | -       | VNI1 value (mutually exclusive with vni2) |
| vni2              | int      | -       | VNI2 value (mutually exclusive with vni1) |
| bind_device       | string   | -       | Bind interface (default: any) |
| pmtudisc          | string   | -       | MTU discovery mode (do/dont/want) |

## output.zmq Parameters
| Parameter         | Type     | Default | Description |
|-------------------|----------|---------|-------------|
| host              | string   | -       | Destination IP |
| port              | int      | -       | Destination port |
| hwm               | int      | -       | ZMQ high watermark |
| service_tag       | int      | -       | Service tag |

## output.file Parameters
| Parameter         | Type     | Default | Description |
|-------------------|----------|---------|-------------|
| name              | string   | -       | Output filename |

## output.rotating_file Parameters
| Parameter          | Type     | Default | Description |
|--------------------|----------|---------|-------------|
| file_root          | string   | -       | Output directory |
| max_file_interval  | string   | -       | Max duration per file |