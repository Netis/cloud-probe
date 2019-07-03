# 关于
在使用本项目实现网络数据镜像的过程中，常常需要将 pktminerg 安装到需要抓取流量的客户机中。
为了减少对客户机上其他程序的干扰，就需要对 pktminerg 程序做一些资源使用限制（使用固定的 cpu 核，控制内存用量），可以参考以下两种方法：


# 方法1
使用 pktminerg 自带的 cpu 亲和性参数（--cpu ID set cpu affinity ID）
示例：```pktminerg -i eth0 -r 192.168.0.100 --cpu 2```
这种方法简单易行，一般推荐这种方法。

# 方法2
使用 scripts 目录下的脚本 limit_cpu_mem.sh 对 pktminerg 的 cpu 和内存做限制。
该脚本使用了 Linux 的 cgroup 机制，对 pktminerg 进程运行的 cpu 和内存进行了控制。
示例：```sh limit_cpu_mem.sh 2```
这种方法在 pktminerg 进程重启时，需要重新运行脚本设置。

虽然这种方法同时对 cpu 和内存进行了限制，比上面第一种方法多了对内存的控制，但 pktminerg 程序本身一般占用内存比较固定（大约500M），所以没有特殊需求的情况下，一般推荐第一种方法。

