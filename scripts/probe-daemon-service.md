# 说明
1. 在安装 agent-daemon 安装包后（比如 rpm 包），请修改/etc/probe-daemon.conf。
2. 使用如下命令控制 agent-daemon 服务：
```
systemctl enable agent-daemon   #自启agent-daemon
systemctl disable agent-daemon  #取消agent-daemon
systemctl start agent-daemon    #启动agent-daemon
systemctl stop agent-daemon     #停止agent-daemon
systemctl restart agent-daemon  #重启agent-daemon
```
