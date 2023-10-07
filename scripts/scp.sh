#!/usr/bin/expect -f

set timeout 10
spawn scp -p [lindex $argv 0] root@[lindex $argv 1]:[lindex $argv 3]
expect {
    "password" {send "[lindex $argv 2]\r";}
    "yes/no" {send "yes\r";exp_continue}
}
expect eof
exit
