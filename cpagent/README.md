### 命令行
```bash
./cpagent --tasks tasks.json --enable-dpdk-dumpcap --cpu-set 1,2 --unix-socket cpagent.socket
```

参数说明:
* unix-socket: listen to a unix socket and accept commands from the `cpdaemon`
* enable-dpdk-dumpcap: 启动dpdk-dumpcap，这样会初始化 EAL 环境
* set-cpu-affinity: 设置cpu亲和性
* cpu-set: 绑定到指定cpus
* tasks: 任务列表配置文件
