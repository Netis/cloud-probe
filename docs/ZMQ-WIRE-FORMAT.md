# cpworker ZMQ Output — Wire Format

This document specifies the on-the-wire format produced by the `zmq` output of **cpworker**.
It is intended for anyone writing a receiver / decoder.

---

## 1. Socket model

* cpworker creates a **`ZMQ_PUSH`** socket and calls `zmq_connect("tcp://<host>:<port>")`.
* The receiver creates a **`ZMQ_PULL`** socket and calls `zmq_bind(...)`.
* **One ZMQ message = one batch** containing multiple records (packets / heartbeat).
* ZMQ `PUSH`/`PULL` preserves message ordering per connection.

Configuration (`cpworker/examples/libpcap_zmq.json`):

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

> `slice` (output-level, not shown above) truncates each packet to at most `slice` bytes.
> Set it to `0`/unset when the full payload is needed. Note that `slice` still leaves at
> least an Ethernet + one VLAN header so the record framing stays valid.

---

## 2. Byte order and conventions

* All multi-byte integer fields in the batch header and packet header are **network byte
  order (big-endian)**, produced via `htons()` / `htonl()`.
* The 4-byte MPLS-like tag is a **host-order bit-field** written with `memcpy()` (see §5).
  On the little-endian hosts cpworker targets, its byte layout is fixed and documented below.
* `sizeof(zmq_pkt_batch_hdr_t) == 24`, `sizeof(zmq_pkt_hdr_t) == 16`.

---

## 3. Batch header (24 bytes, fixed)

| Offset | Size | Field | Encoding | Description |
| --- | --- | --- | --- | --- |
| 0 | 2 | `version` | `htons` | Format version, currently **`2`** (`ZMQ_BATCH_PKTS_VERSION`) |
| 2 | 2 | `pkts_num` | `htons` | Number of records following the header (packets **and** heartbeats) |
| 4 | 4 | `keybit` | `htonl` | Holds `service_tag` (`batch_hdr.keybit = htonl(service_tag)`) |
| 8 | 16 | `uuid` | raw bytes | Probe UUID, 16 bytes, dashes removed |

```c
typedef struct {
    uint16_t version;   // 2
    uint16_t pkts_num;
    uint32_t keybit;
    uint8_t  uuid[16];
} zmq_pkt_batch_hdr_t;   // sizeof == 24
```

---

## 4. Record layout

Every record is:

| Offset | Size | Field | Description |
| --- | --- | --- | --- |
| 0 | 2 | `pkt_data_len` (`htons`) | Length of the frame that follows (`length`, see below) |
| 2 | 16 | `zmq_pkt_hdr_t` | Packet header, see §6 |
| 18 | `pkt_data_len` | `frame` | Ethernet (+VLAN) + 4-byte MPLS tag + L3 payload |

There is **no explicit record type field**. The receiver distinguishes a normal packet from
a heartbeat by inspecting the EtherType of the frame (§7).

### 4.1 `length` computation

In `zmq_send_packet()`:

```c
uint16_t length = (uint16_t)(caplen <= 65531 ? caplen : 65531) + sizeof(mpls_header);
```

i.e. `length = min(captured_length, 65531) + 4`, and `pkt_data_len == length`.

---

## 5. Frame layout

The original Ethernet frame is rewritten: the EtherType (or the innermost VLAN's EtherType)
is replaced with **`0x8847` (MPLS)**, and a 4-byte private MPLS-like tag is inserted before
the L3 payload.

Without VLAN:

```
+---------+---------+----------+--------+-----------+
| dst MAC | src MAC | 0x88 0x47| MPLS 4 | IP ...    |
|  6 B    |  6 B    |  2 B     |  4 B   |           |
+---------+---------+----------+--------+-----------+
```

With one or more stacked VLAN tags:

```
+---------+---------+--------+--------+----------+--------+-----------+
| dst MAC | src MAC | 0x8100 | VLAN.. | 0x8847   | MPLS 4 | IP ...    |
|  6 B    |  6 B    |  2 B   |        | (innermost VLAN ethertype)  |
+---------+---------+--------+--------+----------+--------+-----------+
```

### 5.1 MPLS-like tag (4 bytes)

`make_mpls_hdr()` builds a 32-bit value from bit-fields and `memcpy`s it into the buffer.
On little-endian hosts the resulting bytes are:

| Byte | Value | Meaning |
| --- | --- | --- |
| 0 | `0x80 \| (direct << 3)` | `magic_number = 1`; `direct` = packet direction |
| 1 | `(service_tag >> 4) & 0xff` | high 8 bits of `service_tag` |
| 2 | `((service_tag & 0x0f) << 4) \| 0x01` | low 4 bits of `service_tag`; `bottom = 1` |
| 3 | `0xFF` | reserved / TTL |

`direct` values (`cpworker/src/pkt_dir.h`):

| `direct` | Value | Byte 0 |
| --- | --- | --- |
| `PKT_DIR_NONCHECK` | 0 | `0x80` |
| `PKT_DIR_INCOMING` | 1 | `0x88` |
| `PKT_DIR_OUTGOING` | 2 | `0x90` |
| `PKT_DIR_UNKNOWN` | -1 | (record dropped, never sent) |

> **Direction is only available here.** The MPLS-like tag carries request/response direction
> and the `service_tag`. Packets with `direct == PKT_DIR_UNKNOWN` are dropped and never
> appear in the stream.

Example tags:

| `direct` | `service_tag` | Bytes |
| --- | --- | --- |
| incoming (1) | 0 | `88 00 01 FF` |
| outgoing (2) | 0 | `90 00 01 FF` |
| incoming (1) | 0x1A2 | `88 1A 21 FF` |

---

## 6. Packet header `zmq_pkt_hdr_t` (16 bytes, big-endian)

| Offset | Size | Field | Description |
| --- | --- | --- | --- |
| 0 | 4 | `tv_sec` | Timestamp seconds (**32-bit — subject to the 2038 problem**) |
| 4 | 4 | `tv_usec` | Timestamp microseconds |
| 8 | 4 | `caplen` | **Original captured length + 4** (includes the MPLS tag), not the raw caplen |
| 12 | 4 | `len` | **Original wire length + 4** (includes the MPLS tag) |

```c
typedef struct {
    uint32_t tv_sec;  // caution: unix 2038 problem
    uint32_t tv_usec;
    uint32_t caplen;  // original caplen + sizeof(mpls_header)
    uint32_t len;     // original wire len + sizeof(mpls_header)
} zmq_pkt_hdr_t;
```

> Note: `pkt_data_len` (the framing value) and `pkt_hdr.caplen` are equal
> (`min(caplen,65531) + 4`), while `pkt_hdr.len` uses the *uncapped* original length + 4.
> Receivers should advance by `pkt_data_len`.

---

## 7. Heartbeat record

A heartbeat is a normal-looking record whose frame payload is a 14-byte Ethernet header
with all-zero MAC addresses and **EtherType `0xFFFF`** (`ZMQ_HEARTBEAT_ETHER_TYPE`). There is
no MPLS tag and no payload.

| Offset | Size | Value |
| --- | --- | --- |
| 0 | 2 | `pkt_data_len = 14` |
| 2 | 16 | `zmq_pkt_hdr_t` with current time, `caplen = len = 14` |
| 18 | 14 | 14 zero bytes, except EtherType `0xFFFF` at offset 12 |

A heartbeat is generated at most every `heartbeat_ms` (when configured, `> 0`) and is
**flushed immediately** (it triggers a batch flush).

Detection on the receiver side: if the frame's EtherType (bytes 12–13 of the frame) is
`0xFFFF`, treat the record as a heartbeat.

---

## 8. Batch flush rules

`zmq_flush_packet()` sends the current batch and resets the buffer when any of the following
happens:

| Condition | Constant |
| --- | --- |
| Record count reaches the limit | `ZMQ_PKTS_FLUSH_MAX_NUM = 65535` |
| Time since the first packet in the batch exceeds 1 second | `ZMQ_PKTS_FLUSH_MAX_DUR_SEC = 1` |
| The buffer would exceed the maximum size | `ZMQ_MAX_BATCH_BUF_SIZE = 1048576` (1 MiB) |
| A heartbeat is generated | — |
| `zmq_send()` would block and is skipped | `ZMQ_DONTWAIT` — the batch is counted as dropped |

The send uses `ZMQ_DONTWAIT`; on failure the batch is dropped and counted in
`error_drop_batches` / `error_drop_packets`.

---

## 9. Full message diagram

```
+----------------------- batch header (24 B) -----------------------+
| version=2 | pkts_num | keybit | uuid[16]                            |
+--------------------------------------------------------------------+
| pkt_data_len | zmq_pkt_hdr (16 B) | frame (pkt_data_len B)         |  record 0
+--------------------------------------------------------------------+
| pkt_data_len | zmq_pkt_hdr (16 B) | frame (pkt_data_len B)         |  record 1
+--------------------------------------------------------------------+
| ...                                                                |
```

Total message size = `24 + Σ (2 + 16 + pkt_data_len)`.

---

## 10. Worked example

One packet, no VLAN, `service_tag = 0`, all-zero UUID, `direct = INCOMING`,
`tv_sec = 0x11223344`, `tv_usec = 0x55667788`, original `caplen = 96`, original `len = 96`.
Then `length = 96 + 4 = 100 = 0x64`.

```text
offset  bytes                             meaning
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
56      88 00 01 FF                       MPLS-like tag (incoming, service_tag=0)
60      ...                               L3 payload (82 B = 96 - 14)
```

Total message size = `24 + 2 + 16 + 100 = 142` bytes.
