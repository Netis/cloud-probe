#!/bin/sh
p=`ps -ef|grep $1|grep -v grep|grep -v get_pid_with_container|grep -v pktminerg|awk '{print $2}'`
ps -ef|grep $p|awk '{if( $3=="'$p'" ) print $2}'| awk 'NR==1 {print $1}'
