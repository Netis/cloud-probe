#!/usr/bin/env python
#  -*- coding: utf-8 -*-
from __future__ import print_function
import zmq
import time
import struct
import sys
import os
import getopt

grekey_file_dict = {}

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

#Global header for pcap 2.4
def pcap_global_header():
    return struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 0xFFFF, 1)


#pcap packet header that must preface every packet
def pcap_packet_header(ts_sec, ts_usec, caplen, length):
    return struct.pack("<IIII", ts_sec, ts_usec, caplen, length)


def gre_eth_header():
    return struct.pack(">HIHIBB", 0,0,0,0, 0x08, 0x00)


def gre_ip_header(length, checksum):
    return struct.pack(">BBHHBBBBHII", 0x45, 0, length, 0, 0x40, 0, 0x40, 0x2f, checksum, 0x7F000001, 0x7F000001)


def gre_header(keybit):
    return struct.pack(">HHI", 0x2000, 0x6558, keybit)


def construct_pkt_bytes(ts_sec, ts_usec, caplen, length, keybit, pkt_data_len, pkt_data):
    gre_eth_hdr_len = 14
    gre_ip_hdr_len = 20
    gre_hdr_len = 8
    gre_caplen = gre_eth_hdr_len + gre_ip_hdr_len + gre_hdr_len + pkt_data_len
    gre_length =  gre_caplen
    if length > caplen:
        gre_length =  gre_eth_hdr_len + gre_ip_hdr_len + gre_hdr_len + length
    pkt_bytes = b''.join([
        pcap_packet_header(ts_sec, ts_usec, gre_caplen, gre_length),
        gre_eth_header(),
        gre_ip_header(gre_ip_hdr_len + gre_hdr_len + pkt_data_len, 0xffff), # TODO: handle checksum
        gre_header(keybit),
        pkt_data
    ])
    return pkt_bytes


def create_pcap(config, keybit, ts_sec, suffix_id):
    cur_time = time.localtime(ts_sec)
    file_path_str = time.strftime(config["file_template"], cur_time)
    file_path = "%s_%d"%(file_path_str, suffix_id)
    directory = os.path.dirname(file_path)
    if not os.path.exists(directory):
        os.makedirs(directory)
    print("Open new file:  %s"%file_path)
    pcap_file = open(file_path, 'a+b')
    pcap_file.write(pcap_global_header())
    return pcap_file


def get_pcapfile(config, keybit, ts_sec):
    pcap_file = None
    global grekey_file_dict
    if keybit in grekey_file_dict:
        suffix_id, pcap_ts, pcap_file = grekey_file_dict[keybit]
        span_time = config["span_time"]
        if (ts_sec // span_time) != (pcap_ts // span_time):
            pcap_file.close()
            file_path = os.path.abspath(pcap_file.name)
            target_path = file_path + ".pcap"
            print("Rename file to: %s"%target_path)
            os.rename(file_path, target_path)
            pcap_file = create_pcap(config, keybit, ts_sec, suffix_id)
            grekey_file_dict[keybit] = (suffix_id, ts_sec, pcap_file)
    else:
        suffix_id = len(grekey_file_dict) + config["base_suffixid"]
        pcap_file = create_pcap(config, keybit, ts_sec, suffix_id)
        grekey_file_dict[keybit] = (suffix_id, ts_sec, pcap_file)
    return pcap_file


def parse_message(config, message):
    header_size = 8
    version, pkt_num, keybit = struct.unpack(">HHI", message[:header_size])
    #print("%d %d %d %d"%(version, pkt_num, keybit, len(message)))
    pkt_pos = header_size
    for i in range(pkt_num):
        pkt_data_len, ts_sec, ts_usec, caplen, length = struct.unpack(">HIIII", message[pkt_pos:pkt_pos+18])
        pkt_pos += 18
        pkt_data = message[pkt_pos : pkt_pos + pkt_data_len]
        pkt_bytes = construct_pkt_bytes(ts_sec, ts_usec, caplen, length, keybit, pkt_data_len, pkt_data)
        pcapfile = get_pcapfile(config, keybit, ts_sec)
        pcapfile.write(pkt_bytes)
        pkt_pos += pkt_data_len


def server_loop(config):
    context = zmq.Context()
    socket = context.socket(zmq.PULL)
    socket.bind("tcp://*:%d"%(config["zmq_port"]))
    while True:
        message = socket.recv()
        parse_message(config, message)


def usage():
    print(
"""Usage:
python recvzmq.py [--span_time seconds] -z port_num -t /path/file_template
-z or --zmq_port:\tzmq bind port
-t or --file_template:\tfile template. Examle: /opt/pcap_cache/nic0/%Y%m%d%H%M%S
-s or --span_time:\tpcap span time interval. Default: 10, Unit: seconds.
-b or --base_suffixid:\tpcap file name suffix id will start from this base id. Default 0. Example: 100
-v or --version:\tversion info
-h or --help:\t\thelp message
""")


def parse_args(cfg_dict):
    if len(sys.argv) == 1:
        usage()
        sys.exit()
    try:
        options, args = getopt.getopt(sys.argv[1:], "hvz:t:s:b:",
                                      ["help", "version", "zmq_port=", "file_template=", "span_time=", "base_suffixid="])
    except getopt.GetoptError as e:
        eprint(e)
        sys.exit(-1)

    for name, value in options:
        if name in ("-h", "--help"):
            usage()
            sys.exit()
        elif name in ("-v", "--version"):
            print('recvzmq version 1.0.0')
            sys.exit()
        elif name in ("-z", "--zmq_port"):
            cfg_dict["zmq_port"] = int(value)
        elif name in ("-t", "--file_template"):
            cfg_dict["file_template"] = value
        elif name in ("-s", "--span_time"):
            cfg_dict["span_time"] = int(value)
        elif name in ("-b", "--base_suffixid"):
            cfg_dict["base_suffixid"] = int(value)
    if "zmq_port" not in cfg_dict:
        eprint("require param: -z zmq_port")
        sys.exit(-1)
    if "file_template" not in cfg_dict:
        eprint("require param: -t /path/file_template/%Y%m%d/%Y%m%d%H/%Y%m%d%H%M%S")
        sys.exit(-1)

config = {"span_time": 10, "base_suffixid": 0}
parse_args(config)
server_loop(config)

