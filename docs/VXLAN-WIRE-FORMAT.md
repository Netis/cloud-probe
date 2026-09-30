# cpworker VXLAN Output — Wire Format

This document specifies the on-the-wire format produced by the `vxlan` output of **cpworker**.
It is intended for anyone writing a receiver / decoder.

The outer header follows RFC 7348, but bytes 4–7 of the VXLAN header carry a private tag
(direction, service tag, observation tag) instead of a plain VNI. Two tag formats exist, selected
by `vni1` or `vni2` in the output configuration.

---

## 1. Transport

* cpworker sends one **UDP datagram over IPv4** per packet (or per fragment, see §7) to
  `vxlan.host:vxlan.port` (default port `4789`). The source address and port are chosen by the
  kernel; `bind_device` pins the egress interface.
* `pmtudisc` sets `IP_MTU_DISCOVER` on the socket, which controls the DF bit of the outer IPv4
  header (`dont` → DF = 0; `do` / `want` → DF = 1).

Configuration (`cpworker/examples/libpcap_vxlan1.json`):

```json
{
    "type": "vxlan",
    "vxlan": {
        "host": "2.2.2.2",
        "port": 4789,
        "capture_time": false,
        "vni1": 1,
        "bind_device": "eth1"
    }
}
```

Exactly one of `vni1` and `vni2` must be set. Setting both, or neither, is a config error.

---

## 2. UDP payload layout

```
+---------------------+------------------------------+----------------------------+
| VXLAN header (8 B)  | inner frame (length B)       | capture time (8 B)         |
|                     |                              | only if capture_time: true |
+---------------------+------------------------------+----------------------------+
```

* **Inner frame**: the captured Ethernet frame, unmodified. `length = min(caplen, slice, 65535)`,
  where `slice` applies only when `> 0`.
* **Capture time** (optional): appended after the inner frame, see §6.

---

## 3. VXLAN header (8 bytes)

| Offset | Size | Value | Description |
| --- | --- | --- | --- |
| 0 | 1 | `0x08` | Flags: I bit set (RFC 7348 §5) |
| 1 | 3 | `00 00 00` | Reserved |
| 4 | 4 | tag | Private tag: `vni1` format (§4) or `vni2` format (§5) |

Packet direction (`cpworker/src/pkt_dir.h`) is determined by `req_pattern`:

| Direction | Value | Notes |
| --- | --- | --- |
| `PKT_DIR_NONCHECK` | 0 | No `req_pattern` configured |
| `PKT_DIR_INCOMING` | 1 | Request |
| `PKT_DIR_OUTGOING` | 2 | Response |
| `PKT_DIR_UNKNOWN` | -1 | Packet dropped, never sent |

---

## 4. `vni1` format: service tag (CPM API v1)

The configured `vni1` value is a **service tag**, the same concept as `service_tag` in the GRE
and ZMQ outputs. cpworker keeps the low 24 bits of the value (larger values are logged as a
warning and truncated).

The tag is written through the `pa_tag_t` bit-field (`output_vxlan.c`). On the little-endian
hosts cpworker targets, the bytes are:

| Byte | With a direction (`req_pattern` set) | Without a direction (`NONCHECK`) |
| --- | --- | --- |
| 4 | high nibble: direction (1 or 2); low nibble: 0 | bits 16–23 of `vni1` |
| 5 | high nibble: 0; low nibble: bits 8–11 of `vni1` | bits 8–15 of `vni1` |
| 6 | bits 0–7 of `vni1` | bits 0–7 of `vni1` |
| 7 | check byte (§4.1) | check byte (§4.1) |

Consequences:

* **With a direction, only the low 12 bits of `vni1` are sent.** The receiver reads the service
  tag as `((byte5 & 0x0F) << 8) | byte6` and the direction as `byte4 >> 4`.
* Without a direction, bytes 4–6 carry the low 24 bits of `vni1` unchanged. For a service tag
  in `0x000–0xFFF`, this decodes the same way, with direction 0.
* When the CPM strategy has no service tag, cpdaemon sets `vni1 = 0xFFFFFF`. The receiver then
  sees service tag `0xFFF`. Without a direction, byte 4 is `0xFF`.

### 4.1 Check byte

Byte 7 (reserved by RFC 7348) carries an 8-bit check value that identifies the datagram as
carrying the private tag. It is computed after bytes 4–6 are written and byte 7 is set to 0:

1. Take the first 42 bytes of the UDP payload: the 8-byte VXLAN header plus the first 34 bytes
   of the inner frame (sized for Ethernet + IPv4, but no header is parsed; with VLAN tags or
   IPv6 these are simply the first 34 bytes).
2. Start from `sum = 0x4A3B2D1C` (32-bit) and add the 21 byte pairs as **little-endian**
   16-bit words: `sum += b[2i] | (b[2i+1] << 8)`.
3. Fold twice: `sum = (sum >> 16) + (sum & 0xFFFF)`.
4. Check byte = `sum & 0xFF`. There is no one's complement.

```c
uint32_t sum = 0x4a3b2d1c;
for (int i = 0; i < 42; i += 2)
    sum += b[i] | (b[i + 1] << 8);
sum = (sum >> 16) + (sum & 0xffff);
sum = (sum >> 16) + (sum & 0xffff);
uint8_t check = sum & 0xff;
```

If the inner frame plus the capture-time trailer is shorter than 34 bytes, the computation also
covers bytes past the end of the datagram (left over in cpworker's send buffer), and the
receiver cannot reproduce the check byte.

---

## 5. `vni2` format: observation tag (CPM API v2)

The configured `vni2` value is a 32-bit **observation tag**. cpworker adds the direction to it
and writes the sum in network byte order:

```c
vx_vni = htonl(vni2 + direction);   // bytes 4..7
```

cpdaemon builds `vni2` from the CPM strategy (`Vni2Tag` in
`cpdaemon/pkg/cpm/worker_task_builder.go`):

| Bits | Field | Width | Source |
| --- | --- | --- | --- |
| 0–1 | `resourcePointDirection` | 2 | Always 0 in the config; cpworker adds the direction |
| 2–6 | `observationPointId` | 5 | CPM strategy (default 1) |
| 7 | `extensionFlag` | 1 | CPM strategy (default 0) |
| 8–31 | `observationDomainId` | 24 | CPM strategy (default 1) |

On the wire:

| Byte | Content |
| --- | --- |
| 4–6 | `observationDomainId` (bytes 4–6 are the RFC 7348 VNI field) |
| 7 | `extensionFlag << 7 \| observationPointId << 2 \| direction` |

Rules:

* **Bits 0–1 of `vni2` must be 0.** Otherwise adding the direction carries into
  `observationPointId`. cpworker does not check this.
* There is no check byte.
* A standard RFC 7348 receiver sees the observation domain ID as the VNI.

---

## 6. Capture time trailer

With `capture_time: true`, 8 bytes are appended after the inner frame:

| Offset (after frame) | Size | Encoding | Description |
| --- | --- | --- | --- |
| 0 | 4 | `htonl` | Capture time, seconds (32-bit, **subject to the 2038 problem**) |
| 4 | 4 | `htonl` | Nanoseconds (libpcap microseconds × 1000) |

The receiver can tell only from configuration that the trailer is present. Neither the VXLAN
header nor the inner frame indicates it.

---

## 7. Split

With `split.max_payload_size > 0`, a TCP/UDP packet whose L4 payload exceeds the limit is
split into several inner frames. Each is sent in its own datagram with the same tag and, if
enabled, its own capture-time trailer. For `vni1`, the check byte is computed per datagram.

---

## 8. How cpdaemon chooses the format

cpdaemon generates the cpworker config from the CPM sync strategy
(`cpdaemon/pkg/cpm/worker_task_builder.go`):

| `apiVersion` | Field | Value |
| --- | --- | --- |
| unset or `v1` | `vni1` | `serviceTag` if present, else `0xFFFFFF` |
| other (`v2`) | `vni2` | `Vni2Tag` built from `observationDomainIds`, `observationPointIds` and `extensionFlag` (§5) |

---

## 9. Worked examples

Inner frame starts with (34 bytes):

```text
aa bb cc dd ee ff 11 22 33 44 55 66 08 00    Ethernet, EtherType IPv4
45 00 00 54 12 34 40 00 40 06 00 00          IPv4 ...
0a 00 00 01 0a 00 00 02                      src 10.0.0.1, dst 10.0.0.2
```

VXLAN header for each case:

| Config | Direction | VXLAN header (8 B) |
| --- | --- | --- |
| `vni1 = 0x1A2` | NONCHECK (0) | `08 00 00 00 00 01 A2 F5` |
| `vni1 = 0x1A2` | INCOMING (1) | `08 00 00 00 10 01 A2 05` |
| `vni1 = 0x1A2` | OUTGOING (2) | `08 00 00 00 20 01 A2 15` |
| `vni1 = 0xFFFFFF` (no service tag) | INCOMING (1) | `08 00 00 00 10 0F FF 62` |
| `vni1 = 0x123456` | INCOMING (1) | `08 00 00 00 10 04 56 B9` (only `0x456` survives) |
| `vni2 = 0xDF024` (domain 3568, point 9) | NONCHECK (0) | `08 00 00 00 00 0D F0 24` |
| `vni2 = 0xDF024` | INCOMING (1) | `08 00 00 00 00 0D F0 25` |
| `vni2 = 0xDF024` | OUTGOING (2) | `08 00 00 00 00 0D F0 26` |
