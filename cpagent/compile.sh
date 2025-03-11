#!/bin/sh

gcc \
    src/main.c src/taskconf.c src/cjson_utils.c src/output_zmq.c contrib/cJSON/cJSON.c \
    -I src -I contrib \
    -lzmq \
    -o cpagent