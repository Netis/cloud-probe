# About

We support docker for packet-agent. In this mode, you can attach packet-agent container to another with shared network card, without intrude into another docker to install packet-agent.

You can build docker image from docker/Dockerfile.


# Build steps
1. Build docker image. Now we use centos:6 as base image.
```shell
[deploy@localhost docker]$ docker build -f Dockerfile -t centos-packet-agent:v1 .

[deploy@localhost docker]$ docker images
REPOSITORY                                                                   TAG                 IMAGE ID            CREATED             SIZE
centos-packet-agent                                                          v1                  06472824fd4a        8 seconds ago       262.7 MB 
```


2. Run docker container. The container with packet-agent should share network card with first one(running the application which packet-agent monitor.)
```shell
[deploy@localhost ~]# docker run -itd --privileged=true centos:6 /bin/bash
<CONTAINER HASH ID>

[deploy@localhost ~]# docker ps
CONTAINER ID        IMAGE      COMMAND             CREATED             STATUS              PORTS               NAMES
f03b1a137e06        centos:6   "/bin/bash"         16 minutes ago      Up 16 minutes                           high_carson


[deploy@localhost ~]# docker run -itd --privileged=true --network=container:high_carson centos-packet-agent:v1 /bin/bash
<CONTAINER HASH ID>

[deploy@localhost ~]# docker ps
CONTAINER ID        IMAGE                    COMMAND             CREATED             STATUS              PORTS               NAMES
a6dc13dbf2f0        centos-packet-agent:v1   "/bin/bash"         2 minutes ago       Up 2 minutes                            clever_swirles
f03b1a137e06        centos:6                 "/bin/bash"         18 minutes ago      Up 18 minutes                           high_carson
```

3. Log into container with packet-agent.
```shell
[deploy@localhost ~]# docker attach clever_swirles
[root@6b47b08a55d3 /]# ifconfig eth0 promisc
[root@6b47b08a55d3 /]# pktminerg -i eth0 -r 172.16.1.201
```



