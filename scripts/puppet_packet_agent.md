# 说明
1. 在 master 主机上安装 puppetserver 程序。 </br>
```
# 配置源
# https://yum.puppet.com/<PLATFORM_NAME>-release-<OS ABBREVIATION>-<OS VERSION>.noarch.rpm
# https://apt.puppet.com/<PLATFORM_VERSION>-release-<VERSION CODE NAME>.deb
sudo rpm -Uvh https://yum.puppet.com/puppet6-release-el-7.noarch.rpm
<or>
wget https://apt.puppet.com/puppet6-release-xenial.deb
sudo dpkg -i puppet6-release-xenial.deb

# 安装puppetserver
systemctl stop puppetserver  # <or> service puppetserver stop
yum install puppetserver  # <or> apt-get install puppetserver
puppetserver ca setup
systemctl start puppetserver # <or> service puppetserver start
```
2. 在 agent 主机上安装 puppet-agent. <br/>
```
# 配置源(过程同上)
# 安装puppet-agent
sudo yum install puppet-agent # <or> sudo apt-get install puppet-agent, <or> sudo zypper install puppet-agent
```
3. 在 master/agent 上配置好 FQDN 格式的主机名。一般在 /etc/hostname 下配置主机名，在/etc/hosts配置IP/FQDN/主机名对应关系。</br>
```
# Example:
# master主机名centos7, FQDN:centos7.server, IP: 192.168.229.20
# agent主机名ubuntu, FQDN:ubuntu.client, IP: 192.168.229.30
# ...

$ cat /etc/hosts
...
192.168.229.20         centos7.server   centos7   # master/agent主机的/etc/hosts都要配置
192.168.229.30         ubuntu.client    ubuntu    # master/agent主机的/etc/hosts都要配置
192.168.229.31         ubuntu2.client    ubuntu2    # master/agent主机的/etc/hosts都要配置
192.168.229.32         ubuntu3.client    ubuntu3    # master/agent主机的/etc/hosts都要配置
127.0.0.1    puppet            # master上可能需要添加，用于SSL认证证书请求及发送
...

```
4. 在 agnet 上，配置好 master 的主机名。一般在 $confdir/puppet.conf 文件的 [main] 配置段，配置 server/certname 属性。 </br>
```
# $confdir : 
# *nix root users: /etc/puppetlabs/puppet
# Non-root users: ~/.puppetlabs/etc/puppet

# puppet.conf ：
...
[main]
server = centos7.server
certname = ubuntu.client
```
5. 在 master 上，拷贝 script/puppet_packet_agent.pp 到 $codedir/environments/production/manifests 下。</br>
```
# $codedir : 
# *nix root users: /etc/puppetlabs/code
# *nix non-root users: ~/.puppetlabs/etc/code
```
6. 在 agent 主机启动 puppet service, 默认每隔半小时同 master 同步一次并触发更新安装流程。</br>
也可在 agent 主机上手动执行 /opt/puppetlabs/bin/puppet agent -t 命令触发同步流程，将 netis-packet-agent 程序安装到当前 agent 上。</br>
```
sudo puppet resource service puppet ensure=running enable=true  # <or> 'puppet agent -t' 手动触发
```

