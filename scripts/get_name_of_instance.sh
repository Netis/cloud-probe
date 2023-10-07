#!/bin/sh
virsh list|awk 'NR>2 {print $2}'
