# Packet-Agent libpcap 缓存与最大支持流量评测

# 测试环境与方法

pktminerg version 0.3.2 (rev: 7d844a7 build: 2019-01-21 10:27:50)
libpcap version 1.5.3

8 核 vSphere 虚拟机：Intel(R) Xeon(R) CPU E5-2670 0 @ 2.60GHz
内存 16GB

使用 --buffsize 参数控制 pktminerg libpcap 缓存大小，使用tcpreplay往网卡发包，逐次增加发包速率，记录 pktminerg 出现丢包时的发包速率。

# 测试结果


|libpcap buffsize| 进程内存占用 | 最大支持流量 |
|----------------|--------------|--------------|
|18 MB |	32 MB |	549 Mbps|
|36 MB |	50 MB |	705 Mbps|
|64 MB |	79 MB |	862 Mbps|
|128 MB |	145 MB |	900 Mbps|

