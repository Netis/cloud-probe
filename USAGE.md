# Usage
```
Generic options:
  -v [ --version ]      show version.
  -h [ --help ]         show help.

Allowed options:
  -i [ --interface ] NIC          interface to capture packets
  -f [ --pcapfile ] PATH          specify pcap file for offline mode, mostly 
                                  for test
  -r [ --remoteip ] IP            set gre remote ip
  -k [ --keybit ] BIT (=1)        set gre key bit; BIT defaults 1
  -s [ --snaplen ] LENGTH (=2048) set snoop packet snaplen; LENGTH defaults 
                                  2048 and units byte
  -t [ --timeout ] TIME (=3)      set snoop packet timeout; TIME defaults 3 and
                                  units second
  -b [ --buffsize ] SIZE (=256)   set snoop buffer size; SIZE defaults 256 and 
                                  units MB
  -c [ --count ] COUNT (=0)       exit after receiving count packets; COUNT 
                                  defaults; count<=0 means unlimited
  -p [ --priority ]               set high priority mode
  --cpu ID                        set cpu affinity ID
  --expression FILTER             filter packets with FILTER; FILTER as same as
                                  tcpdump BPF expression syntax
  --dump                          specify dump file, mostly for integrated test
  --nofilter                      force no filter; only use when you confirm 
                                  that the snoop interface is different from 
                                  the gre interface

```
<br>

## Paramters

* interface<br>
Network interface to capture packets (eth0, eth1...). Required in live mode.

* remoteip, keybit<br>
Parameters of GRE channel:
remoteip：GRE channel remote IP addresss (required)
keybit：GRE protocol keybit parameter to distinguish the channel to remote IP

* cpu, priority<br>
cpu：set CPU affinity to improve performance, it's recommended to isolate target CPU core in grub before set affinity.
priority: set high priority for the process to improve performance.

* nofilter<br>
When pktminerg capture packets on one network interface and send GRE packet to remote IP via the same interface,
we need to filter the captured output GRE packet, or else there will be infinite loop.
The filter is on by default with libpcap packet filter which will cause performance downgrade.
You can set the "--nofilter" paramter to close the filter function to improve performance with the following scenarios:
  1. The packet capture network interface is different from the GRE output interface.
  2. There is no IP set on the packet capture network interface. (In this scenario, the program can't work without --nofilter)

* expression<br>
expression: This parameter is used to match and filter the packets (syntax is same with tcpdump).
This parameter will be invalid if "nofilter" parameter is set.


## Example
* Network interface example<br>
pktminerg -i eth0 -r 172.16.1.201

* Pcap file example<br>
pktminerg -f sample.pcap -r 172.16.1.201

* Filter example<br>
pktminerg -i eth0 -r 172.16.1.201 --expression '172.16.1.12'

* CPU affinity and high priority example<br>
pktminerg -i eth0 -r 172.16.1.201 --cpu 1 -p

* nofilter example, the packet capture network interface must different from the GRE output interface<br>
pktminerg -i eth0 -r 172.16.1.201 --nofilter