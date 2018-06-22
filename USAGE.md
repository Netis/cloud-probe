# Usage
```
Generic options:
  -v [ --version ]              show version.
  -h [ --help ]                 show help.
Allowed options:
  -i [ --interface ] arg        interface to capture packets.
  -f [ --pcapfile ] arg         specify pcap file for offline mode, mostly for
                                test.
  -s [ --snaplen ] arg (=2048)  set snoop packet snaplen. Default=2048B.
  -t [ --timeout ] arg (=3)     set snoop packet timeout. Default=3s.
  -b [ --buffsize ] arg (=256)  set snoop buffer size. Default=256MB.
  -r [ --remoteip ] arg         set gre remote ip.
  -k [ --keybit ] arg (=1)      set gre key bit.
  -c [ --count ] arg (=0)       Exit after receiving count packets. Default=0,
                                No limit if count<=0.
  --cpu arg                     set cpu affinity.
  -p [ --priority ]             set high priority mode.
  --dump                        specify dump file, mostly for integrated test.
  --nofilter                    force no filter, only use when you confirm that
                                the snoop interface is different from the gre
                                interface.
  --expression arg              filter packets like tcpdump expression syntax.
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
pktminerg -i eth0 -r 172.16.1.201 --cpu 0 -p --nofilter
