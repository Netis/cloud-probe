# 关于
在使用本项目实现网络数据镜像的过程中，常常需要将 pktminerg 安装到需要抓取流量的客户机中。</br>
为了减少对客户机上其他程序的干扰，就需要对 pktminerg 程序做一些资源使用限制（使用固定的 cpu 核，控制CPU百分比和内存用量），可以参考以下两种方法：</br>


# 方法1
使用 pktminerg 自带的 cpu 亲和性参数（--cpu ID set cpu affinity ID）</br>
示例：```pktminerg -i eth0 -r 192.168.0.100 --cpu 2```</br>
这种方法简单易行，一般推荐这种方法。</br>

# 方法2
使用 scripts 目录下的脚本 limit_cpu_mem.sh 对 pktminerg 的 cpu 和内存做限制。</br>
该脚本使用了 Linux 的 cgroup 机制，对 pktminerg 进程运行的 cpu 和内存进行了控制。</br>
示例：
```
# sh limit_cpu_mem.sh  $CPU_SET_ID  $CFS_QUOTA_US  $MEM_LIMIT
# CPU_SET_ID : 逗号分隔的cpu cores，指定pktminerg运行的核。
# CFS_QUOTA_US ： 每100ms的cpu时间中，分配给pktminerg的时长，单位微秒。
# MEM_LIMIT： 限制内存用量，可采用M/K/G等单位。无单位则为字节。
sh limit_cpu_mem.sh 2 10000 800M # 运行在CPU core 2上，10%CPU用量，800M内存限制
```
* MEM_LIMIT 对 pcap 缓存无效。pcap 缓存自定义需使用-b参数指定。
* MEM_LIMIT 仅对第一次配置后新增部分的内存开销有效。
* 这种方法在 pktminerg 进程重启时，需要重新运行脚本设置。

虽然这种方法同时对 cpu 和内存进行了限制，比上面第一种方法多了对内存的控制，但 pktminerg 程序本身一般占用内存比较固定（大约500M），所以没有特殊需求的情况下，一般推荐第一种方法。</br>

