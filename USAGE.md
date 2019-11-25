# Usage

## Usage for pktminerg
```
Generic options:
  -v [ --version ]      show version.
  -h [ --help ]         show help.

Allowed options:
  -i [ --interface ] NIC          interface to capture packets
  -B [ --bind_device ] BIND       send GRE packets from this binded
                                  device.(Not available on Windows)
  -M [ --pmtudisc_option ] MTU    Select Path MTU Discovery strategy.  
                                  pmtudisc_option may be either do (prohibit 
                                  fragmentation, even local one), want (do 
                                  PMTU discovery, fragment locally when packet
                                  size is large), or dont (do not set DF flag)
  -f [ --pcapfile ] PATH          specify pcap file for offline mode, mostly
                                  for test
  -r [ --remoteip ] IPs           set gre remote IPs(ipv4/ipv6), seperate by ','
                                  Example: -r 8.8.4.4,fe80::250::11
  -k [ --keybit ] BIT (=1)        set gre key bit; BIT defaults 1
  -s [ --snaplen ] LENGTH (=2048) set snoop packet snaplen; LENGTH defaults 
                                  2048 and units byte
  -t [ --timeout ] TIME (=3)      set snoop packet timeout; TIME defaults 3 and
                                  units second
  -b [ --buffsize ] SIZE (=256)   set snoop buffer size; SIZE defaults 256 and 
                                  units MB
  -c [ --count ] COUNT (=0)       exit after receiving count packets; COUNT 
                                  defaults; count<=0 means unlimited
  -p [ --priority ]               set high priority mode (Not supported on Windows platform)
  --cpu ID                        set cpu affinity ID (Not supported on Windows platform)
  --expression FILTER             filter packets with FILTER; FILTER as same as
                                  tcpdump BPF expression syntax
  --dump                          specify dump file, mostly for integrated test
  --nofilter                      force no filter; In online mode, only use when GRE interface
                                  is set via CLI, AND you confirm that the snoop interface is
                                  different from the gre interface.
  --proto_config                  (This is a test feature.) The protocol extension's configuration in
                                  JSON string format. If not set, packet-agent will use default
                                  tunnel protocol (GRE with key) to export packet.
                                  Now only supportted on Linux platform.

```

### Paramters

* interface<br>
Network interface to capture packets (eth0, eth1...). Required in live mode.
<br>

* pmtudisc_option<br>
Select Path MTU Discovery strategy.pmtudisc_option may be either do (prohibit fragmentation, even local one), 
want (do PMTU discovery, fragment locally when packet size is large), or dont (do not set DF flag).
<br>

* bind_device<br>
Send GRE packets from this binded device. Sending will be failed when this device is down.
<br>

* remoteip, keybit<br>
Parameters of GRE channel:
remoteip：GRE channel remote IP addresss (required)
keybit：GRE protocol keybit parameter to distinguish the channel to remote IP
<br>

* cpu, priority<br>
cpu：set CPU affinity to improve performance, it's recommended to isolate target CPU core in grub before set affinity.
priority: set high priority for the process to improve performance.
<br>

* nofilter<br>
When pktminerg capture packets on one network interface and send GRE packet to remote IP via the same interface,
we need to filter the captured output GRE packet, or else there will be infinite loop.
The filter is on by default with libpcap packet filter which will cause performance downgrade.
You can set the "--nofilter" paramter to close the filter function to improve performance with the following scenarios:
  1. The packet capture network interface is different from the GRE output interface.
  2. There is no IP set on the packet capture network interface. (In this scenario, the program can't work without --nofilter)
<br>

* expression<br>
expression: This parameter is used to match and filter the packets (syntax is same with tcpdump).
This parameter will be invalid if "nofilter" parameter is set.
<br>

* proto_config<br>
(This is a test feature.)
'proto_config' contain the protocol extension's configuration in JSON string format.
Protocol extension are various plugins of different tunnel protocol for exporting packet as several dynamic library (.so),
The dynamic library must be located in same directory as pktminerg with file name 'lib<extension_name>.so'.
If this parameter is not set, packet-agent will use default tunnel protocol(GRE with key) to export packet.
Now only supportted on Linux platform.
The configuration examples (proto_erspan_type3):
```
[
    {
        "ext_title": "proto_erspan_type3",
        "entry": "packet_agent_proto_extionsion_entry",
        "ext_params": {
            "use_default_header": false,
            "enable_vlan": true,
            "vlan": 1024,
            "enable_sequence": true,
            "sequence_begin": 10000,
            "enable_timestamp": true
        }
    }
]
```
Now supported extension:
proto_erspan_type1
proto_erspan_type2
proto_erspan_type3
proto_gre

<br>

### Examples
* Network interface example
```
pktminerg -i eth0 -r 172.16.1.201
```
* Pcap file example
```
pktminerg -f sample.pcap -r 172.16.1.201
```
* Filter example
```
pktminerg -i eth0 -r 172.16.1.201 --expression '172.16.1.12'
```
* CPU affinity and high priority example (Not supported on Windows Platform)
```
pktminerg -i eth0 -r 172.16.1.201 --cpu 1 -p
```
* nofilter example, the packet capture network interface must different from the GRE output interface
```
pktminerg -i eth0 -r 172.16.1.201 --nofilter
```

<br>
<br>
<br>
<br>
<br>
<br>

## Usage for pcapcompare
```
Generic options:
  -v [ --version ]       show version.
  -h [ --help ]          show help.

Allowed options:
  --lpcap PCAP_PATH      pcap file 1
  --rpcap PCAP_PATH      pcap file 2
```

### Paramters
* lpcap<br>
Left pcap file to compare.
<br>

* rpcap<br>
Right pcap file to compare.
<br>

### Examples
```
pcapcompare --lpcap /path/to/left_file.pcap --rpcap /path/to/right_file.pcap
```

<br>
<br>
<br>
<br>
<br>
<br>

## Usage for gredump
```
Generic options:
  -v [ --version ]             show version.
  -h [ --help ]                show help.

Allowed options:
  -i [ --interface ] NIC       interface to capture packets.
  -f [ --pcapfile ] PATH       specify pcap file for offline mode, mostly for test.
  -s [ --sourceip ] SRC_IP     source ip filter. (Unsupported on IPv6)
  -r [ --remoteip ] DST_IP     gre remote ip filter. (Unsupported on IPv6)
  -k [ --keybit ] BIT          gre key bit filter.
  -o [ --output ] OUT_PCAP     output pcap file
  -c [ --count ] MAX_NUM (=0)  Exit after receiving count packets. Default=0, 
                               No limit if count<=0.
```

### Paramters
* interface<br>
Network interface to capture gre packets (eth0, eth1...). Required in live mode.
<br>

* pcapfile<br>
Input packets from the specified pcap file for offline mode. Mostly for test.
<br>

* sourceip, remoteip, keybit<br>
sourceip：Drop captured GRE packet if its source ip doesn't match specified sourceip.<br>
remoteip：Drop captured GRE packet if its remote ip doesn't match specified remoteip.<br>
keybit：Drop captured GRE packet if its GRE channel keybit doesn't match specified keybit.
<br>
Known issue: packet with fragments, sourceip filter, remoteip filter is NOT supported with IPv6.

* output<br>
Output pcap file
<br>

* count<br>
Exit after receiving count packets. Default=0, No limit if count <= 0.
<br>

### Examples
```
gredump -i eth0 -o /path/to/gredump_output.pcap
```

