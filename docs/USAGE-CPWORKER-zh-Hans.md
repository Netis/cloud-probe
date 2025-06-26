# cpworker 使用手册

## 概述
cpworker 是基于 libpcap 的网络抓包工具，支持多种输出方式和智能流量控制。

## 配置模版
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

更多配置示例，请查看: [examples](../cpworker/examples)

## 顶层参数列表
| 参数	             | 类型	   | 默认值	  | 说明  |
|-------------------|---------|---------|-----|
| cpu_affinity      | string  | -       | 设置cpu亲和性 |
| log_level         | string  | INFO    | 日志级别，可选值：DEBUG, INFO, WARN, ERROR |
| control           | object  | -       | 控制面通信接口 |
| control.type      | string  | -       | 控制面通信接口类型，当前支持：unix |
| control.unix.path | string  | -       | unix socket 文件 |


## task参数列表

| 参数	                       | 类型    | 默认值    | 说明  |
|-----------------------------|---------|----------|-------|
| req_pattern                 | object  | -        | 数据包方向判断 |
| req_pattern.type	          | string  | -        | 数据包方向识别模式 (auto/custom)，未配置时方向为 NONCHECK |
| req_pattern.custom.pattern  | string	| -	       | 使用 nic.eth0 是会被替换为 eth0 的IP |
| capturer                    | object  | -	       | 数据包捕获参数 |
| capturer.type               | string  | -       | 当前支持: libpcap |

## capturer.libpcap 参数列表
| 参数	             | 类型	   | 默认值	  | 说明  |
|-------------------|---------|---------|-----|
| interface	        | string  | -	    | 抓包网卡名称 (必填) |
| snaplen           | int     | 2048    | 抓包是裁切的长度 |
| netns             | string  | -       | 网卡所属的网络命名空间 |
| bpf               | string  | -       | bpf 过滤条件 |
| buffer_size_mb    | int     | -       | buffer_size 大小，单位为: mb |
| timeout_ms        | int     | -       | 超时时间，单位为: ms |

## output 参数列表
| 参数	             | 类型	   | 默认值	  | 说明  |
|-------------------|---------|---------|-----|
| type              | string  | -        | 输出类型 |
| rate_limit_mbps   | int     | -        | 最大输出速率，默认不限制，单位：mbps |
| slice             | int     | -        | 输出是数据包裁切的大小，默认不裁切|

## output.gre 参数列表
| 参数	             | 类型	   | 默认值	  | 说明  |
|-------------------|---------|---------|-----|
| host              | string  | -       | 目的ip |
| bind_device       | string  | -       | 绑定数据包发送接口，默认不指定|
| pmtudisc          | string  | -       | 指定MTU发现模式，可选值: do, dont, want |
| service_tag       | int     | -       | 服务标签 |

## output.vxlan 参数列表
| 参数	             | 类型	   | 默认值	  | 说明  |
|-------------------|---------|---------|-----|
| host              | string  | -       | 目的ip |
| port              | int     | -       | 目的端口 |
| capture_time      | bool    | -       | 是否在数据包上增加捕获时间 |
| vni1              | int     | -       | vni1的值，不能同时设置 vni1和vni2 |
| vni2              | int     | -       | vni2的值，不能同时设置 vni1和vni2 |
| bind_device       | string  | -       | 绑定数据包发送接口，默认不指定|
| pmtudisc          | string  | -       | 指定MTU发现模式，可选值: do, dont, want |

## output.zmq 参数列表
| 参数	             | 类型	   | 默认值	  | 说明  |
|-------------------|---------|---------|-----|
| host              | string  | -       | 目的ip |
| port              | int     | -       | 目的端口 |
| hwm               | int     | -       | zmq水位值 |
| service_tag       | int     | -       | 服务标签 |

## output.file 参数列表
| 参数	             | 类型	   | 默认值	  | 说明  |
|-------------------|---------|---------|-----|
| name              | string  | -       | 输出文件 |

## output.rotating_file 参数列表
| 参数	             | 类型	   | 默认值	  | 说明  |
|-------------------|---------|---------|-----|
| file_root         | string  | -       | 输出文件目录 |
| max_file_interval | string  | -       | 单个文件的最大时长 |

