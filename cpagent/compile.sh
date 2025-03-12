#!/bin/sh

gcc \
    src/main.c \
    src/taskconf.c \
    src/output_zmq.c \
    src/log.c \
    src/cjson_utils.c \
    contrib/cJSON/cJSON.c \
    -L/root/dpdk-install/lib64 \
    -Isrc -Icontrib \
    -lzmq -lpcap
