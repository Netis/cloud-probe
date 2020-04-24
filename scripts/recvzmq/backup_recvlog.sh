#!/bin/bash

backup_log_and_clear() {
    LOG_FILE_NAME=$1
    tar --overwrite -czf ${LOG_FILE_NAME}.tar.gz ${LOG_FILE_NAME}
    >${LOG_FILE_NAME}
}

LOG_FILE=$1

while true
do
    sleep 86400
    if [ -f "$LOG_FILE" ]
    then
        backup_log_and_clear $LOG_FILE
    fi
done

