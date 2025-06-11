## Linux系统

### 前置要求
* libpcap

### 下载
进入发布页面 `https://github.com/Netis/cloud-probe/releases` 选择合适的二进制包，比如：cloud-probe-0.9.0-linux-amd64.tar.gz

### 安装
通过删除 `/usr/local/cloud-probe` 文件夹（如果存在）移除之前安装的 cloud-probe 版本，然后将刚下载的压缩包解压到 /usr/local 目录，从而在 /usr/local/cloud-probe 中创建全新的 cloud-probe 目录结构：

```bash
$ rm -rf /usr/local/cloud-probe && tar -C /usr/local -xzf cloud-probe-0.9.0-linux-amd64.tar.gz
```

（可能需要以 root 权限或通过 sudo 单独执行每条命令。）

不要将压缩包解压到已存在的 `/usr/local/cloud-probe` 目录中，这会导致 cloud-probe 安装损坏。

将 /usr/local/cloud-probe/bin 添加到 PATH 环境变量中。
可以通过在您的 $HOME/.profile 或 /etc/profile（系统级安装）中添加以下行实现：

```bash
export PATH=$PATH:/usr/local/cloud-probe/bin
```

注意：配置文件的修改可能需要重新登录才能生效。如需立即生效，可以直接运行上面命令或通过 source $HOME/.profile 命令加载配置文件。

打开终端并执行以下命令验证是否安装成功：
```bash
$ cpworker -v
$ cpdaemon version
```

确认该命令输出了已安装的 cloud-probe 组件的版本信息。
