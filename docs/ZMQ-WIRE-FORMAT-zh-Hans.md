# cpworker ZMQ 输出 — 线格式（Wire Format）

本文档描述 **cpworker** 的 `zmq` 输出在网络上产生的字节格式，供接收端 / 解码器开发者参考。

---

## 1. Socket 模型

* cpworker 创建 **`ZMQ_PUSH`** socket，调用 `zmq_connect("tcp://<host>:<port>")`。
* 接收端创建 **`ZMQ_PULL`** socket，调用 `zmq_bind(...)`。
* **一条 ZMQ message = 一个 batch**，内含多条记录（packet / heartbeat）。
* ZMQ `PUSH`/`PULL` 保证同一连接内的消息有序。

配置示例（`cpworker/examples/libpcap_zmq.json`）：

```json
{
    "tasks": [
        {
            "req_pattern": { "type": "auto" },
            "capturer": {
                "type": "libpcap",
                "libpcap": { "interface": "eth0", "snaplen": 2048, "buffer_size_mb": 256 }
            },
            "outputs": [
                {
                    "type": "zmq",
                    "rate_limit_mbps": 10,
                    "zmq": {
                        "host": "127.0.0.1",
                        "port": 5555,
                        "hwm": 1000,
                        "service_tag": 0,
                        "uuid": "796d506a-46a1-4f4e-bd9a-6075a49ac9f8",
                        "heartbeat_ms": 0
                    }
                }
            ]
        }
    ]
}
```

> output 级的 `slice`（上例未展示）会把每个包截断到最多 `slice` 字节。需要完整 payload
> 时请设为 `0`/不设置。`slice` 仍会保留至少「以太头 + 一个 VLAN 头」，以保证记录分帧有效。

---

## 2. 字节序与约定

* batch 头与 packet 头里的多字节整数字段一律为**网络字节序（大端）**，由
  `htons()` / `htonl()` 生成。
* 4 字节 MPLS 类标签是**主机序位域**，用 `memcpy()` 直接写入（见 §5）。在 cpworker
  面向的小端主机上，其字节布局固定，下文已给出。
* `sizeof(zmq_pkt_batch_hdr_t) == 24`，`sizeof(zmq_pkt_hdr_t) == 16`。

---

## 3. Batch 头（固定 24 字节）

| 偏移 | 长度 | 字段 | 编码 | 说明 |
| --- | --- | --- | --- | --- |
| 0 | 2 | `version` | `htons` | 格式版本，当前为 **`2`**（`ZMQ_BATCH_PKTS_VERSION`） |
| 2 | 2 | `pkts_num` | `htons` | 头之后跟随的记录条数（**含 packet 与 heartbeat**） |
| 4 | 4 | `keybit` | `htonl` | 实际存放 `service_tag`（`batch_hdr.keybit = htonl(service_tag)`） |
| 8 | 16 | `uuid` | 原始字节 | 探针 UUID 去掉横杠后的 16 字节 |

```c
typedef struct {
    uint16_t version;   // 2
    uint16_t pkts_num;
    uint32_t keybit;
    uint8_t  uuid[16];
} zmq_pkt_batch_hdr_t;   // sizeof == 24
```

---

## 4. 记录布局

每条记录为：

| 偏移 | 长度 | 字段 | 说明 |
| --- | --- | --- | --- |
| 0 | 2 | `pkt_data_len`（`htons`） | 紧随其后的帧长度（即 `length`，见下） |
| 2 | 16 | `zmq_pkt_hdr_t` | 包头，见 §6 |
| 18 | `pkt_data_len` | `frame` | 以太头（+VLAN）+ 4 字节 MPLS 标签 + L3 payload |

**没有显式的记录类型字段**。接收端通过检查帧的 EtherType 来区分普通包和 heartbeat（§7）。

### 4.1 `length` 的计算

在 `zmq_send_packet()` 中：

```c
uint16_t length = (uint16_t)(caplen <= 65531 ? caplen : 65531) + sizeof(mpls_header);
```

即 `length = min(抓包长度, 65531) + 4`，且 `pkt_data_len == length`。

---

## 5. 帧布局

原始以太帧被改写：把 EtherType（或最内层 VLAN 的 EtherType）替换为
**`0x8847`（MPLS）**，并在 L3 payload 之前插入 4 字节私有的 MPLS 类标签。

无 VLAN：

```
+---------+---------+----------+--------+-----------+
| dst MAC | src MAC | 0x88 0x47| MPLS 4 | IP ...    |
|  6 B    |  6 B    |  2 B     |  4 B   |           |
+---------+---------+----------+--------+-----------+
```

有一层或多层堆叠 VLAN：

```
+---------+---------+--------+--------+----------+--------+-----------+
| dst MAC | src MAC | 0x8100 | VLAN.. | 0x8847   | MPLS 4 | IP ...    |
|  6 B    |  6 B    |  2 B   |        |（最内层 VLAN 的 ethertype）  |
+---------+---------+--------+--------+----------+--------+-----------+
```

### 5.1 MPLS 类标签（4 字节）

`make_mpls_hdr()` 用位域拼出一个 32 位值再 `memcpy` 进缓冲区。在小端主机上得到的字节为：

| 字节 | 值 | 含义 |
| --- | --- | --- |
| 0 | `0x80 \| (direct << 3)` | `magic_number = 1`；`direct` = 报文方向 |
| 1 | `(service_tag >> 4) & 0xff` | `service_tag` 高 8 位 |
| 2 | `((service_tag & 0x0f) << 4) \| 0x01` | `service_tag` 低 4 位；`bottom = 1` |
| 3 | `0xFF` | 保留 / TTL |

`direct` 取值（`cpworker/src/pkt_dir.h`）：

| `direct` | 值 | 字节 0 |
| --- | --- | --- |
| `PKT_DIR_NONCHECK` | 0 | `0x80` |
| `PKT_DIR_INCOMING` | 1 | `0x88` |
| `PKT_DIR_OUTGOING` | 2 | `0x90` |
| `PKT_DIR_UNKNOWN` | -1 |（记录被丢弃，不会发出） |

> **方向信息只在这里。** MPLS 类标签携带请求/响应方向和 `service_tag`。
> `direct == PKT_DIR_UNKNOWN` 的报文会被丢弃，不会出现在流里。

标签示例：

| `direct` | `service_tag` | 字节 |
| --- | --- | --- |
| incoming (1) | 0 | `88 00 01 FF` |
| outgoing (2) | 0 | `90 00 01 FF` |
| incoming (1) | 0x1A2 | `88 1A 21 FF` |

---

## 6. 包头 `zmq_pkt_hdr_t`（16 字节，大端）

| 偏移 | 长度 | 字段 | 说明 |
| --- | --- | --- | --- |
| 0 | 4 | `tv_sec` | 时间戳秒（**32 位 — 存在 2038 问题**） |
| 4 | 4 | `tv_usec` | 时间戳微秒 |
| 8 | 4 | `caplen` | **原始抓包长度 + 4**（含 MPLS 标签），不是原始 caplen |
| 12 | 4 | `len` | **原始线上长度 + 4**（含 MPLS 标签） |

```c
typedef struct {
    uint32_t tv_sec;  // caution: unix 2038 problem
    uint32_t tv_usec;
    uint32_t caplen;  // original caplen + sizeof(mpls_header)
    uint32_t len;     // original wire len + sizeof(mpls_header)
} zmq_pkt_hdr_t;
```

> 注意：分帧用的 `pkt_data_len` 与 `pkt_hdr.caplen` 相等
> （`min(caplen,65531) + 4`），而 `pkt_hdr.len` 用的是**未截断**的原始长度 + 4。
> 接收端应按 `pkt_data_len` 前移。

---

## 7. Heartbeat 记录

heartbeat 是一条看起来正常的记录，其帧内容为 14 字节以太头：MAC 全 0，
EtherType 为 **`0xFFFF`**（`ZMQ_HEARTBEAT_ETHER_TYPE`）。没有 MPLS 标签，也没有 payload。

| 偏移 | 长度 | 值 |
| --- | --- | --- |
| 0 | 2 | `pkt_data_len = 14` |
| 2 | 16 | `zmq_pkt_hdr_t`，时间为当前时间，`caplen = len = 14` |
| 18 | 14 | 14 字节全 0，仅偏移 12 处的 EtherType 为 `0xFFFF` |

当配置了 `heartbeat_ms`（`> 0`）时，最多每隔该间隔生成一次，并**立即 flush**
（生成心跳会触发一次 batch flush）。

接收端识别方式：若帧的 EtherType（帧内偏移 12–13）为 `0xFFFF`，即视为 heartbeat。

---

## 8. Batch flush 规则

`zmq_flush_packet()` 在满足以下任一条件时发送当前 batch 并重置缓冲区：

| 条件 | 常量 |
| --- | --- |
| 记录数达到上限 | `ZMQ_PKTS_FLUSH_MAX_NUM = 65535` |
| 距 batch 内首包时间超过 1 秒 | `ZMQ_PKTS_FLUSH_MAX_DUR_SEC = 1` |
| 缓冲区将超过最大尺寸 | `ZMQ_MAX_BATCH_BUF_SIZE = 1048576`（1 MiB） |
| 生成 heartbeat | — |
| `zmq_send()` 会被阻塞时跳过 | `ZMQ_DONTWAIT` — 该 batch 记为丢弃 |

发送使用 `ZMQ_DONTWAIT`；失败时整批丢弃，计入 `error_drop_batches` / `error_drop_packets`。

---

## 9. 完整消息示意图

```
+----------------------- batch header (24 B) -----------------------+
| version=2 | pkts_num | keybit | uuid[16]                            |
+--------------------------------------------------------------------+
| pkt_data_len | zmq_pkt_hdr (16 B) | frame (pkt_data_len B)         |  记录 0
+--------------------------------------------------------------------+
| pkt_data_len | zmq_pkt_hdr (16 B) | frame (pkt_data_len B)         |  记录 1
+--------------------------------------------------------------------+
| ...                                                                |
```

消息总长 = `24 + Σ (2 + 16 + pkt_data_len)`。

---

## 10. 实例

一个包、无 VLAN、`service_tag = 0`、UUID 全 0、`direct = INCOMING`、
`tv_sec = 0x11223344`、`tv_usec = 0x55667788`、原始 `caplen = 96`、原始 `len = 96`。
于是 `length = 96 + 4 = 100 = 0x64`。

```text
偏移    字节                             含义
------  -------------------------------   ------------------------------------------
0       00 02                             version = 2
2       00 01                             pkts_num = 1
4       00 00 00 00                       keybit (service_tag) = 0
8       00 00 00 00 00 00 00 00           uuid (16 B)
        00 00 00 00 00 00 00 00
24      00 64                             pkt_data_len = 100
26      11 22 33 44                       tv_sec
30      55 66 77 88                       tv_usec
34      00 00 00 64                       caplen = 100 (96 + 4)
38      00 00 00 64                       len    = 100 (96 + 4)
42      aa bb cc dd ee ff                 dst MAC
48      11 22 33 44 55 66                 src MAC
54      88 47                             EtherType = MPLS
56      88 00 01 FF                       MPLS 类标签（incoming, service_tag=0）
60      ...                               L3 payload（82 B = 96 - 14）
```

消息总长 = `24 + 2 + 16 + 100 = 142` 字节。
