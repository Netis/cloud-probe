# cpworker VXLAN 输出 — 线格式（Wire Format）

本文档描述 **cpworker** 的 `vxlan` 输出在网络上产生的字节格式，供接收端 / 解码器开发者参考。

外层头部遵循 RFC 7348，但 VXLAN 头的第 4–7 字节承载的不是普通 VNI，而是 Netis 私有标签（方向、
业务标签、观测标签）。标签有两种格式，由输出配置中的 `vni1` 或 `vni2` 选择。

---

## 1. 传输

* cpworker 为每个报文（或每个拆分片段，见 §7）向 `vxlan.host:vxlan.port`（默认端口 `4789`）发送
  一个 **IPv4 UDP 数据报**。源地址和源端口由内核选择；`bind_device` 固定出接口。
* `pmtudisc` 设置 socket 的 `IP_MTU_DISCOVER`，决定外层 IPv4 头的 DF 位（`dont` → DF = 0；
  `do` / `want` → DF = 1）。

配置示例（`cpworker/examples/libpcap_vxlan1.json`）：

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

`vni1` 与 `vni2` 必须且只能设置一个。同时设置或都不设置都属于配置错误。

---

## 2. UDP 负载布局

```
+---------------------+------------------------------+----------------------------+
| VXLAN 头 (8 B)      | 内层帧 (length B)            | 捕获时间 (8 B)             |
|                     |                              | 仅 capture_time: true 时   |
+---------------------+------------------------------+----------------------------+
```

* **内层帧**：捕获到的以太网帧，原样转发。`length = min(caplen, slice, 65535)`，其中 `slice`
  仅在 `> 0` 时生效。
* **捕获时间**（可选）：追加在内层帧之后，见 §6。

---

## 3. VXLAN 头（8 字节）

| 偏移 | 长度 | 值 | 说明 |
| --- | --- | --- | --- |
| 0 | 1 | `0x08` | 标志位：I 位置 1（RFC 7348 §5） |
| 1 | 3 | `00 00 00` | 保留 |
| 4 | 4 | 标签 | Netis 标签：`vni1` 格式（§4）或 `vni2` 格式（§5） |

报文方向（`cpworker/src/pkt_dir.h`）由 `req_pattern` 判定：

| 方向 | 值 | 说明 |
| --- | --- | --- |
| `PKT_DIR_NONCHECK` | 0 | 未配置 `req_pattern` |
| `PKT_DIR_INCOMING` | 1 | 请求 |
| `PKT_DIR_OUTGOING` | 2 | 响应 |
| `PKT_DIR_UNKNOWN` | -1 | 报文被丢弃，不会发出 |

---

## 4. `vni1` 格式：业务标签（CPM API v1）

配置的 `vni1` 值是一个**业务标签**（service tag），与 GRE、ZMQ 输出中的 `service_tag` 是同一
概念。cpworker 保留该值的低 24 位（更大的值会打印警告并截断）。

标签通过 `pa_tag_t` 位域写入（`output_vxlan.c`）。在 cpworker 面向的小端主机上，字节为：

| 字节 | 有方向（配置了 `req_pattern`） | 无方向（`NONCHECK`） |
| --- | --- | --- |
| 4 | 高 4 位：方向（1 或 2）；低 4 位：0 | `vni1` 的第 16–23 位 |
| 5 | 高 4 位：0；低 4 位：`vni1` 的第 8–11 位 | `vni1` 的第 8–15 位 |
| 6 | `vni1` 的第 0–7 位 | `vni1` 的第 0–7 位 |
| 7 | 校验字节（§4.1） | 校验字节（§4.1） |

由此可知：

* **有方向时，`vni1` 只有低 12 位会被发出。** 接收端按 `((byte5 & 0x0F) << 8) | byte6` 读取
  业务标签，按 `byte4 >> 4` 读取方向。
* 无方向时，第 4–6 字节原样携带 `vni1` 的低 24 位。业务标签在 `0–4095` 范围内时，按上面的方式
  解码结果相同，方向为 0。
* CPM 策略中没有业务标签时，cpdaemon 设置 `vni1 = 0xFFFFFF`，接收端看到的业务标签为 `0xFFF`。
  无方向时第 4 字节为 `0xFF`。

### 4.1 校验字节

第 7 字节（RFC 7348 中的保留字节）携带一个 8 位校验值，用于识别该数据报带有 Netis 标签。它在
第 4–6 字节写好、第 7 字节置 0 之后计算：

1. 取 UDP 负载的前 42 字节：8 字节 VXLAN 头加内层帧的前 34 字节（按以太网 + IPv4 的长度取，
   但不解析任何头部；带 VLAN 标签或 IPv6 时就是内层帧的前 34 字节）。
2. 从 `sum = 0x4A3B2D1C`（32 位）开始，把这 21 对字节按**小端** 16 位字累加：
   `sum += b[2i] | (b[2i+1] << 8)`。
3. 折叠两次：`sum = (sum >> 16) + (sum & 0xFFFF)`。
4. 校验字节 = `sum & 0xFF`，不取反码。

```c
uint32_t sum = 0x4a3b2d1c;
for (int i = 0; i < 42; i += 2)
    sum += b[i] | (b[i + 1] << 8);
sum = (sum >> 16) + (sum & 0xffff);
sum = (sum >> 16) + (sum & 0xffff);
uint8_t check = sum & 0xff;
```

如果内层帧加捕获时间尾部不足 34 字节，计算会覆盖数据报末尾之后的字节（cpworker 发送缓冲区中的
残留数据），接收端无法复现该校验字节。

---

## 5. `vni2` 格式：观测标签（CPM API v2）

配置的 `vni2` 值是一个 32 位**观测标签**（observation tag）。cpworker 把方向加到该值上，并以
网络字节序写入：

```c
vx_vni = htonl(vni2 + direction);   // 第 4..7 字节
```

cpdaemon 根据 CPM 策略构造 `vni2`（`cpdaemon/pkg/cpm/worker_task_builder.go` 中的 `Vni2Tag`）：

| 位 | 字段 | 宽度 | 来源 |
| --- | --- | --- | --- |
| 0–1 | `resourcePointDirection` | 2 | 配置中恒为 0，由 cpworker 加上方向 |
| 2–6 | `observationPointId` | 5 | CPM 策略（默认 1） |
| 7 | `extensionFlag` | 1 | CPM 策略（默认 0） |
| 8–31 | `observationDomainId` | 24 | CPM 策略（默认 1） |

线上字节：

| 字节 | 内容 |
| --- | --- |
| 4–6 | `observationDomainId`（第 4–6 字节即 RFC 7348 的 VNI 字段） |
| 7 | `extensionFlag << 7 \| observationPointId << 2 \| direction` |

规则：

* **`vni2` 的第 0–1 位必须为 0。** 否则加上方向后会进位到 `observationPointId`。cpworker 不做
  这项检查。
* 没有校验字节。
* 标准 RFC 7348 接收端看到的 VNI 就是观测域 ID。

---

## 6. 捕获时间尾部

`capture_time: true` 时，在内层帧之后追加 8 字节：

| 偏移（帧之后） | 长度 | 编码 | 说明 |
| --- | --- | --- | --- |
| 0 | 4 | `htonl` | 捕获时间，秒（32 位，**存在 2038 年问题**） |
| 4 | 4 | `htonl` | 纳秒（libpcap 的微秒 × 1000） |

接收端只能从配置得知是否带有该尾部，VXLAN 头和内层帧中都没有标识。

---

## 7. 拆分（split）

`split.max_payload_size > 0` 时，L4 负载超过上限的 TCP/UDP 报文会被拆成多个内层帧。每个内层帧
单独用一个数据报发送，携带相同的标签，启用时也各自带捕获时间尾部。`vni1` 格式的校验字节按每个
数据报分别计算。

---

## 8. cpdaemon 如何选择格式

cpdaemon 根据 CPM 同步策略生成 cpworker 配置（`cpdaemon/pkg/cpm/worker_task_builder.go`）：

| `apiVersion` | 字段 | 值 |
| --- | --- | --- |
| 未设置或 `v1` | `vni1` | 有 `serviceTag` 时取其值，否则为 `0xFFFFFF` |
| 其他（`v2`） | `vni2` | 由 `observationDomainIds`、`observationPointIds` 和 `extensionFlag` 构造的 `Vni2Tag`（§5） |

---

## 9. 实例

内层帧开头（34 字节）：

```text
aa bb cc dd ee ff 11 22 33 44 55 66 08 00    以太网，EtherType IPv4
45 00 00 54 12 34 40 00 40 06 00 00          IPv4 ...
0a 00 00 01 0a 00 00 02                      源 10.0.0.1，目的 10.0.0.2
```

各情况下的 VXLAN 头：

| 配置 | 方向 | VXLAN 头（8 B） |
| --- | --- | --- |
| `vni1 = 0x1A2` | NONCHECK (0) | `08 00 00 00 00 01 A2 F5` |
| `vni1 = 0x1A2` | INCOMING (1) | `08 00 00 00 10 01 A2 05` |
| `vni1 = 0x1A2` | OUTGOING (2) | `08 00 00 00 20 01 A2 15` |
| `vni1 = 0xFFFFFF`（无业务标签） | INCOMING (1) | `08 00 00 00 10 0F FF 62` |
| `vni1 = 0x123456` | INCOMING (1) | `08 00 00 00 10 04 56 B9`（只保留 `0x456`） |
| `vni2 = 0xDF024`（域 3568，观测点 9） | NONCHECK (0) | `08 00 00 00 00 0D F0 24` |
| `vni2 = 0xDF024` | INCOMING (1) | `08 00 00 00 00 0D F0 25` |
| `vni2 = 0xDF024` | OUTGOING (2) | `08 00 00 00 00 0D F0 26` |
