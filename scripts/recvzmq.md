# Usage

## Usage for recvzmq.py
```
python recvzmq.py [--span_time seconds] -z port_num -t /path/file_template -a 4
-z or --zmq_port:       zmq bind port
-t or --file_template:  file template. Examle: /opt/pcap_cache/nic0/%Y%m%d%H%M%S
-s or --span_time:      pcap span time interval. Default: 15, Unit: seconds.
-a or --total_workers:  total worker process count of recvzmq. Default 1.
-v or --version:        version info
-h or --help:           help message
```

### Paramters

* zmq_port<br>
Zeromq bind port to receive message from remote packet agent client.
<br>

* file_template<br>
File path and file name of output pcap, the file name template will be formatted.
Examle: /opt/pcap_cache/nic0/%Y%m%d%H%M%S
%Y%m%d%H%M%S will be formatted to something like 20200415090530, pcap name will be 20200415090530_2_0.pcap, 20200415090530_2_1.pcap
<br>

* span_time<br>
Pcap span time interval. Default: 15, Unit: seconds.
<br>

* total_workers<br>
Total worker process count of recvzmq. Default 1.
Usually, the max capacity for one worker process is 200Mbps.
<br>

### Examples
* Two child process workers
```
python recvzmq.py -s 15 -z 82 -f /opt/pcap_cache/nic0/%Y%m%d%H%M%S -a 2
```
