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

更多配置示例，请查看: [examples](../cpworker/examples)

下文以十六进制表示的值（如 `0xFFF`），在 JSON 配置中须写成十进制（如 `4095`）。

## 顶层参数列表
| 参数	                   | 类型	   | 默认值	  | 说明  |
|-------------------------|---------|---------|-----|
| cpu_affinity            | string  | -       | 设置cpu亲和性 |
| log_level               | string  | INFO    | 日志级别，可选值：DEBUG, INFO, WARN, ERROR |
| control                 | object  | -       | 控制面通信接口 |
| control.type            | string  | -       | 控制面通信接口类型，当前支持：unix |
| control.unix.path       | string  | -       | unix socket 文件 |
| execution_model         | string  | rtc     | 处理数据包的执行模式 (rtc, pipeline) |
| pipeline.buffer_size_mb | int     | -       | pipeline 缓冲区大小，单位 MB（>= 1），execution_model 为 pipeline 时必填 |


## task参数列表

| 参数	                       | 类型    | 默认值    | 说明  |
|-----------------------------|---------|----------|-------|
| req_pattern                 | object  | -        | 数据包方向判断 |
| req_pattern.type	          | string  | -        | 数据包方向识别模式 (auto/custom)，未配置时方向为 NONCHECK |
| req_pattern.custom.pattern  | string	| -	       | 使用 nic.eth0 是会被替换为 eth0 的IP |
| capturer                    | object  | -	       | 数据包捕获参数 |
| capturer.type               | string  | -        | 当前支持: libpcap |

## capturer.libpcap 参数列表
| 参数	             | 类型	   | 默认值	  | 说明  |
|-------------------|---------|---------|-----|
| interface	        | string  | -	    | 抓包网卡名称 (必填) |
| snaplen           | int     | 2048    | 抓包截断长度（1-262144）；0、负数或更大的值按 262144 处理 |
| netns             | string  | -       | 网卡所属的网络命名空间 |
| bpf               | string  | -       | bpf 过滤条件 |
| buffer_size_mb    | int     | 256     | 缓冲区大小，单位 MB（1-2047）；更大的值按 2047 处理 |
| timeout_ms        | int     | 0       | libpcap 包缓冲超时，单位毫秒（>= 0）。0：报文到达后立即交付（immediate mode）。> 0：libpcap 最多缓冲这么多毫秒后成批交付，以延迟换取更少的唤醒次数 |

`timeout_ms: 0` 依赖 `pcap_set_immediate_mode()`，要求运行时 libpcap >= 1.5。发布包 `lib/` 中自带的 libpcap 1.6.2 和各支持平台的系统 libpcap（CentOS 7.9：1.5.3，Ubuntu 22.04：1.10.1）都满足要求。libpcap 更老时，cpworker 会打印 `pcap_set_immediate_mode unavailable` 日志，并退化为 10 ms 的缓冲超时。

## output 参数列表
| 参数	             | 类型	   | 默认值	  | 说明  |
|-------------------|---------|---------|-----|
| type              | string  | -        | 输出类型 |
| rate_limit_mbps   | int     | 0        | 最大输出速率，单位 Mbps（>= 0）；0 表示不限速 |
| slice             | int     | 0        | 输出时数据包截断长度，单位字节（>= 0）；0 表示不截断 |

## output.gre 参数列表
| 参数	             | 类型	   | 默认值	  | 说明  |
|-------------------|---------|---------|-----|
| host              | string  | -       | 目的ip |
| bind_device       | string  | -       | 绑定数据包发送接口，默认不指定|
| pmtudisc          | string  | -       | 指定MTU发现模式，可选值: do, dont, want |
| service_tag       | int     | 0xFFFFFFFF | 业务标签，放在 GRE key 中，28 位（0x0-0xFFFFFFF）；key 的高 4 位携带方向 |

## output.vxlan 参数列表
| 参数	             | 类型	   | 默认值	  | 说明  |
|-------------------|---------|---------|-----|
| host              | string  | -       | 目的ip |
| port              | int     | 4789    | 目的端口（1-65535） |
| capture_time      | bool    | false   | 在内层帧之后追加 8 字节捕获时间 |
| vni1              | int     | -       | 业务标签，VXLAN 标签格式 v1（0x0-0xFFFFFFFF；超过 24 位时保留低 24 位）。配置了 `req_pattern` 时只发出低 12 位（0x0-0xFFF）。vni1 / vni2 必须且只能设置一个 |
| vni2              | int     | -       | 观测标签，VXLAN 标签格式 v2，32 位（0x0-0xFFFFFFFF）；第 0–1 位必须为 0，因为方向会加到该值上。vni1 / vni2 必须且只能设置一个 |
| bind_device       | string  | -       | 绑定数据包发送接口，默认不指定|
| pmtudisc          | string  | -       | 指定MTU发现模式，可选值: do, dont, want |
| split.max_payload_size | int | 0     | 拆分 IPv4/IPv6 上的 TCP/UDP 报文，使每个报文的 L4 负载不超过该字节数（0-65535）；0 表示不拆分。IPv4/IPv6 分片和其他报文原样发送 |
| split.recalculate_checksum | bool | false | 重新计算拆分后报文的 IPv4 头校验和与 TCP/UDP 校验和 |

vni1 / vni2 的字节布局、方向编码和捕获时间格式，见 [VXLAN-WIRE-FORMAT-zh-Hans.md](VXLAN-WIRE-FORMAT-zh-Hans.md)。

## output.zmq 参数列表
| 参数	             | 类型	   | 默认值	  | 说明  |
|-------------------|---------|---------|-----|
| host              | string  | -       | 目的ip |
| port              | int     | -       | 目的端口（1-65535），必填 |
| hwm               | int     | 100     | ZMQ 发送高水位，单位为 batch（每个最大 1 MB）（>= 0）；0 表示不限制（会打印警告） |
| service_tag       | int     | 0xFFFFFFFF | 业务标签，每个报文标签中占 12 位（0x0-0xFFF）；batch 头的 keybit 携带完整的 32 位值 |
| uuid              | string  | ""      | 探针 UUID，用于心跳包标识 |
| heartbeat_ms      | int     | 0       | 心跳间隔（毫秒），范围 0–60000，0 表示禁用心跳 |

## output.file 参数列表
| 参数	             | 类型	   | 默认值	  | 说明  |
|-------------------|---------|---------|-----|
| name              | string  | -       | 输出文件 |

## output.rotating_file 参数列表
| 参数	             | 类型	   | 默认值	  | 说明  |
|-------------------|---------|---------|-----|
| file_root         | string  | -       | 输出文件目录 |
| max_file_interval | int     | 60      | 每个文件的时长，单位秒，到时轮转到新文件（>= 0）；0 表示不轮转 |

