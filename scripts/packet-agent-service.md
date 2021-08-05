# 说明
1. 在安装 packet-agent 安装包后（比如 rpm 包），请修改 /usr/local/etc/pktgd.sh 脚本，将 pktminerg 命令参数中的网卡和远端IP地址修改为你需要的值，也可以添加其他你需要的命令参数。</br>
2. 使用如下命令控制 packet-agent 服务：
```
systemctl enable packet-agent   #将 /usr/local/etc/pktgd.sh 加入系统自启动
systemctl disable packet-agent  #取消 pktgd.sh 系统自启动
systemctl start packet-agent    #启动 pktgd.sh
systemctl stop packet-agent     #停止 pktgd.sh
systemctl restart packet-agent  #重启 pktgd.sh
```
