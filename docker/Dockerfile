FROM docker.io/centos:6

ENV LANG en_US.UTF-8
ENV LANGUAGE en_US.UTF-8
ENV LC_ALL en_US.UTF-8
ENV PATH /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENV LD_LIBRARY_PATH /usr/local/lib64:/usr/local/lib



RUN yum install -y libpcap wget && \
    mkdir /root/install && \
    cd /root/install && \
    wget https://github.com/Netis/packet-agent/releases/download/v0.3.2/netis-packet-agent-0.3.2.el6.x86_64.rpm && \
    rpm -ivh netis-packet-agent-0.3.2.el6.x86_64.rpm 








