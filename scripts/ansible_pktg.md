# 说明
1. 在主控的中心服务器上需要安装有 ansible 程序。如果没有，可以使用类似 yum install ansible 的命令安装。</br>
2. 将需要安装 packet-agent 的机器加入 ansible 的 hosts 文件：比如添加组 [servers_to_install_pktg] 到 /etc/ansible/hosts，并在该组下加入若干机器IP。</br>
3. 拷贝待安装的 packet-agent rpm/deb 到 ansible_pktg.yaml 同一目录下。如果待安装的 rpm/deb 不是 yaml 中指定的 netis-packet-agent-0.3.4.el6.x86_64.rpm / netis-packet-agent-0.3.3_amd64.deb，则将 ansible_pktg.yaml 中 rpm_file/deb_file 修改为你需要的文件名。</br>
4. 执行 ansible-playbook ansible_pktg.yaml 命令，将 packet-agent 程序安装到各个目标机器上。</br>

