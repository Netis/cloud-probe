# cpworker User Manual

## Overview
cpworker is a network packet capture tool built on libpcap, supporting multiple output methods and intelligent traffic control.

## Configuration Template
```json
{
    "cpu_affinity": "1",
    "log_level": "INFO",
    "control": {
        "type": "unix",
        "unix": {
            "path": "/var/run/cloud-probe/cpworker.sock"
        }
    },
    "execution_model": "rtc",
    "pipeline": {
        "buffer_size_mb": 256
    },
    "tasks": [
        {
            "req_pattern": {
                "type": "custom",
                "custom": {
                    "pattern": "host nic.eth0 and port 8011"
                }
            },
            "capturer": {
                "type": "libpcap",
                "libpcap": {
                    "interface": "eth0",
                    "snaplen": 2048,
                    "netns": "/proc/1432897/ns/net",
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
| cpu_affinity       | string   | -       | Set CPU affinity |
| log_level          | string   | INFO    | Log level (DEBUG, INFO, WARN, ERROR) |
| control            | object   | -       | Control plane communication interface |
| control.type       | string   | -       | Control interface type (currently supports: unix) |
| control.unix.path  | string   | -       | Unix socket file path |
| execution_model    | string   | rtc     | Packet process execution model (rtc, pipeline) |
| pipeline.buffer_size_mb | int | -       | Pipeline buffer size in MB (>= 1), required if execution_model is pipeline |

## Task Parameters
| Parameter                     | Type     | Default | Description |
|-------------------------------|----------|---------|-------------|
| req_pattern                   | object   | -       | Packet direction detection |
| req_pattern.type              | string   | -       | Direction mode (auto/custom). NONCHECK if unconfigured |
| req_pattern.custom.pattern    | string   | -       | Pattern where `nic.eth0` will be replaced with eth0's IP |
| capturer                      | object   | -       | Packet capture settings |
| capturer.type                 | string   | -       | Capture type (currently supports: libpcap) |

## capturer.libpcap Parameters
| Parameter        | Type     | Default | Description |
|------------------|----------|---------|-------------|
| interface        | string   | -       | Capture NIC name (required) |
| snaplen          | int      | 2048    | Packet truncation length (1-262144); 0, negative or larger values mean 262144 |
| netns            | string   | -       | Network namespace of the NIC |
| bpf              | string   | -       | BPF filter |
| buffer_size_mb   | int      | 256     | Buffer size in MB (1-2047); larger values mean 2047 |
| timeout_ms       | int      | 0       | libpcap packet buffer timeout in milliseconds (>= 0). 0: deliver each packet as soon as it arrives (immediate mode). > 0: libpcap buffers packets for up to this many milliseconds and delivers them in batches, trading latency for fewer wakeups |

`timeout_ms: 0` relies on `pcap_set_immediate_mode()`, which requires libpcap >= 1.5 at runtime. Both the libpcap 1.6.2 shipped in the release package's `lib/` and the system libpcap on the supported platforms (CentOS 7.9: 1.5.3, Ubuntu 22.04: 1.10.1) meet this. With an older libpcap, cpworker logs `pcap_set_immediate_mode unavailable` and falls back to a 10 ms buffer timeout.

## Output Parameters
| Parameter         | Type     | Default | Description |
|-------------------|----------|---------|-------------|
| type              | string   | -       | Output type |
| rate_limit_mbps   | int      | 0       | Max output rate in Mbps (>= 0); 0 means unlimited |
| slice             | int      | 0       | Packet truncation size in bytes (>= 0); 0 means no truncation |

## output.gre Parameters
| Parameter         | Type     | Default | Description |
|-------------------|----------|---------|-------------|
| host              | string   | -       | Destination IP |
| bind_device       | string   | -       | Bind interface (default: any) |
| pmtudisc          | string   | -       | MTU discovery mode (do/dont/want) |
| service_tag       | int      | 4294967295 | Service tag carried in the GRE key, 28 bits (0-268435455); the high 4 bits of the key carry the direction |

## output.vxlan Parameters
| Parameter         | Type     | Default | Description |
|-------------------|----------|---------|-------------|
| host              | string   | -       | Destination IP |
| port              | int      | 4789    | Destination port (1-65535) |
| capture_time      | bool     | false   | Append an 8-byte capture timestamp after the inner frame |
| vni1              | int      | -       | Service tag, VXLAN tag format v1 (0-4294967295; larger than 24 bits keeps the low 24 bits). With a `req_pattern`, only the low 12 bits (0-4095) are sent. Exactly one of vni1 / vni2 is required |
| vni2              | int      | -       | Observation tag, VXLAN tag format v2, 32 bits (0-4294967295); bits 0-1 must be 0 because the direction is added to the value. Exactly one of vni1 / vni2 is required |
| bind_device       | string   | -       | Bind interface (default: any) |
| pmtudisc          | string   | -       | MTU discovery mode (do/dont/want) |
| split.max_payload_size | int | 0      | Split TCP/UDP packets over IPv4/IPv6 so each carries at most this many L4 payload bytes (0-65535); 0 disables splitting. Other packets are sent unchanged |
| split.recalculate_checksum | bool | false | Recalculate the IPv4 header and TCP/UDP checksums of split packets |

For the byte layout of vni1 / vni2, the direction encoding and the capture timestamp, see [VXLAN-WIRE-FORMAT.md](VXLAN-WIRE-FORMAT.md).

## output.zmq Parameters
| Parameter         | Type     | Default | Description |
|-------------------|----------|---------|-------------|
| host              | string   | -       | Destination IP |
| port              | int      | -       | Destination port (1-65535), required |
| hwm               | int      | 100     | ZMQ send high watermark in batches of up to 1 MB each (>= 0); 0 means unbounded (logged as a warning) |
| service_tag       | int      | 4294967295 | Service tag, 12 bits (0-4095) in each packet label; the batch header keybit carries the full 32-bit value |
| uuid              | string   | ""      | Probe UUID carried in heartbeat packets |
| heartbeat_ms      | int      | 0       | Heartbeat interval in ms (0–60000); 0 disables heartbeat |

## output.file Parameters
| Parameter         | Type     | Default | Description |
|-------------------|----------|---------|-------------|
| name              | string   | -       | Output filename |

## output.rotating_file Parameters
| Parameter          | Type     | Default | Description |
|--------------------|----------|---------|-------------|
| file_root          | string   | -       | Output directory |
| max_file_interval  | int      | 60      | Seconds per file before rotating to a new one (>= 0); 0 means never rotate |