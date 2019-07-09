# 性能测试流程
1. 准备两台机器，一台抓包，另一台接收 GRE 数据包。在抓包机器上配置两张网卡，如 eth1, eth2。
2. 在抓包机器上安装 libpcap, tcpreplay，并按照手册安装 packet-agent 程序：https://github.com/Netis/packet-agent/blob/master/INSTALL.md
3. 运行本项目 scripts 目录下的 test_pktg_perf.sh，使用说明见该脚本 Usage 说明（发送封装后GRE数据包的网卡，最好不要与抓包的网卡不是同一个）：
```
Usage:
    sh test_pktg_perf.sh pcap_file loopx replay_nic gre_recv_ip pktg_cpu_id
        pcap_file: input pcap for tcpreplay to send packets to NIC.
        loopx: use this coefficient to control tcpreplay duration.
        replay_nic: tcpreplay target network interface(eth1, eth2...).
        gre_recv_ip: remote ip to receive gre packet.
        pktg_cpu_id: limit pktminerg to run on this cpu processor id (suggest to NOT use core 0).
Example:
    sh test_pktg_perf.sh input.pcap 5 eth2 192.168.0.1 1

```
4. 运行脚本时会将各种状态（cpu、内存占用，pps等）写入 stats.txt。

