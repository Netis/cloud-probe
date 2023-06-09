#!/bin/sh
virsh domiflist $1|awk 'NR==3 {print $1}'
