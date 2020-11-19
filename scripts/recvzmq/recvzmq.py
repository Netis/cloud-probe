#!/usr/bin/env python
#  -*- coding: utf-8 -*-
from __future__ import print_function
from collections import deque
from  multiprocessing import Process
import zmq
import time
import struct
import sys
import os
import getopt
import traceback

grekey_file_info = None

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


def create_pcap(config, ts_sec, suffix_id):
    cur_time = time.localtime(ts_sec)
    file_path_str = time.strftime(config["file_template"], cur_time)
    file_path = "%s_%d_%d"%(file_path_str, config["total_workers"], suffix_id)
    directory = os.path.dirname(file_path)
    if not os.path.exists(directory):
        os.makedirs(directory)
    if os.path.exists(file_path):
        os.remove(file_path)
    #print("Open new file:  %s"%file_path)
    pcap_file = open(file_path, 'a+b')
    pcap_file.write(pcap_global_header())
    return pcap_file


def get_base_ts(ts_sec, span_time):
    return (ts_sec // span_time) * span_time


def get_pcapfile(config, ts_sec):
    pcap_file = None
    span_time = config["span_time"]
    global grekey_file_info
    if grekey_file_info != None:
        (suffix_id, pcap_ts, pcap_file) = grekey_file_info
        if (ts_sec // span_time) != (pcap_ts // span_time):
            pcap_file.close()
            file_path = os.path.abspath(pcap_file.name)
            target_path = file_path + ".pcap"
            #print("Rename file to: %s"%target_path)
            os.rename(file_path, target_path)
            pcap_file = create_pcap(config, get_base_ts(ts_sec, span_time), suffix_id)
            grekey_file_info = (suffix_id, get_base_ts(ts_sec, span_time), pcap_file)
    else:
        suffix_id = config["base_suffixid"]
        pcap_file = create_pcap(config, get_base_ts(ts_sec, span_time), suffix_id)
        grekey_file_info = (suffix_id, get_base_ts(ts_sec, span_time), pcap_file)
    return pcap_file

def takeFirst(elem):
    return elem[0]

class BatchPktsHandler():

    def __init__(self, config):
        self.PKT_EVICT_TS_TIMEOUT = 7
        self.PKT_EVICT_INTERVAL = 1
        self.PKT_EVICT_BUFF_SIZE = 2 * 1024*1024

        self.config = config
        self.first_msg_realworld_time = 0
        self.first_pkt_realworld_time = 0
        self.first_pkt_ts_time = 0
        self.last_heartbeat_ts = 0
        self.min_realworld_ts_pkt_ts_diff = 0
        self.new_realworld_ts_pkt_ts_diff = 0
        self.pkt_evict_ts_checkpoint = 0
        self.evict_num = 0
        self.msg_dict = {}
        self.evict_pkts_list = []
        self.export_bytearray = bytearray(self.PKT_EVICT_BUFF_SIZE)
        self.export_bytearray_pos = 0
        self.total_drop_pkts = 0

        self.frag_offset = int(self.config["frag_offset"])
        self.frag_offset_roundup = int((self.frag_offset / 2) / 8) * 8

        self.keybit_ipid_map = {}


    def is_working_busy(self):
        return len(self.msg_dict) > self.PKT_EVICT_TS_TIMEOUT + self.PKT_EVICT_INTERVAL


    def unpack_msgpkts_to_evict(self, message):
        header_size = 8
        timeout_drop_pkts = 0
        version, pkt_num, keybit = struct.unpack(">HHI", message[:header_size])
        pkt_pos = header_size
        for j in range(pkt_num):
            pkt_data_len, ts_sec, ts_usec, caplen, length = struct.unpack(">HIIII", message[pkt_pos:pkt_pos+18])
            pkt_pos += 18
            if ts_sec < self.pkt_evict_ts_checkpoint:
                if j == 0 and ts_sec + 1 < self.pkt_evict_ts_checkpoint:  # hack: rely on pktg msg batch max timeout 1s
                    timeout_drop_pkts = pkt_num
                    break
                timeout_drop_pkts += 1
            else:
                pkt_data = message[pkt_pos : pkt_pos + pkt_data_len]
                pkt_info = (ts_sec*1000000 + ts_usec, caplen, length, keybit, pkt_data_len, pkt_data)
                self.evict_pkts_list.append(pkt_info)
            pkt_pos += pkt_data_len
        self.total_drop_pkts += timeout_drop_pkts
        return timeout_drop_pkts


    def construct_pkt_bytes(self, ts_sec, ts_usec, caplen, length, keybit, pkt_data_len, pkt_data):
        gre_eth_hdr_len = 14
        gre_ip_hdr_len = 20
        gre_hdr_len = 8
        gre_ip_layer_max_len = 65535

        if pkt_data_len == 0 and keybit == 0:
            heartbeat_data_len = 4
            struct.pack_into("<IIII", self.export_bytearray, self.export_bytearray_pos, ts_sec, ts_usec,
                             gre_eth_hdr_len + heartbeat_data_len, gre_eth_hdr_len + heartbeat_data_len)
            self.export_bytearray_pos += 16
            struct.pack_into(">HIHIHI", self.export_bytearray, self.export_bytearray_pos, 0,0,0,0, 0xffff, 0)
            self.export_bytearray_pos += gre_eth_hdr_len + heartbeat_data_len
        else:
            ipid = self.get_ipid_from_map(keybit)
            if gre_eth_hdr_len + gre_ip_hdr_len + gre_hdr_len + length > gre_ip_layer_max_len or pkt_data_len > self.frag_offset:
                first_frag_pkt_data_len = self.frag_offset_roundup
                if pkt_data_len <= self.frag_offset_roundup:
                    first_frag_pkt_data_len = int(pkt_data_len / 2 / 8) * 8
                first_frag_pkt_data = pkt_data[0:first_frag_pkt_data_len]
                self.construct_firstfrag_pkt_bytes(ipid, ts_sec, ts_usec, first_frag_pkt_data_len, first_frag_pkt_data_len,
                                                   keybit, first_frag_pkt_data_len, first_frag_pkt_data, is_frag=True)

                last_frag_pkt_data_len = pkt_data_len - first_frag_pkt_data_len
                last_frag_pkt_data = pkt_data[first_frag_pkt_data_len:]
                self.construct_lastfrag_pkt_bytes(ipid, ts_sec, ts_usec, last_frag_pkt_data_len, last_frag_pkt_data_len,
                                                  keybit, first_frag_pkt_data_len, last_frag_pkt_data_len, last_frag_pkt_data)
            else:
                self.construct_firstfrag_pkt_bytes(ipid, ts_sec, ts_usec, caplen, length,
                                                   keybit, pkt_data_len, pkt_data, is_frag=False)

        buff_is_full = False
        if self.export_bytearray_pos >= self.PKT_EVICT_BUFF_SIZE - 65636:
            buff_is_full = True
        return buff_is_full

    def construct_firstfrag_pkt_bytes(self, ipid, ts_sec, ts_usec, caplen, length, keybit, pkt_data_len, pkt_data, is_frag):
        gre_eth_hdr_len = 14
        gre_ip_hdr_len = 20
        gre_hdr_len = 8
        eth_ip_gre_len = 42  # gre_eth_hdr_len + gre_ip_hdr_len + gre_hdr_len
        checksum = 0xffff
        gre_caplen = eth_ip_gre_len + pkt_data_len
        gre_length =  gre_caplen
        if length > caplen:
            gre_length =  eth_ip_gre_len + length

        frag_and_offset = 0x40
        if is_frag:
            frag_and_offset = 0x20

        struct.pack_into("<IIII", self.export_bytearray, self.export_bytearray_pos, ts_sec, ts_usec, gre_caplen, gre_length)
        self.export_bytearray_pos += 16
        struct.pack_into(">HIHIBBBBHHBBBBHIIHHI", self.export_bytearray, self.export_bytearray_pos, 0,0,0,0, 0x08, 0x00,
                         0x45, 0, gre_ip_hdr_len + gre_hdr_len + pkt_data_len,
                         ipid, frag_and_offset, 0, 0x40, 0x2f, checksum, keybit, 0x7F000001,
                         0x2000, 0x6558, keybit)
        self.export_bytearray_pos += eth_ip_gre_len
        if pkt_data_len > 0:
            struct.pack_into("!%ds"%(pkt_data_len), self.export_bytearray, self.export_bytearray_pos, pkt_data)
            self.export_bytearray_pos += pkt_data_len


    def construct_lastfrag_pkt_bytes(self, ipid, ts_sec, ts_usec, caplen, length, keybit, first_frag_pkt_data_len, pkt_data_len, pkt_data):
        gre_eth_hdr_len = 14
        gre_ip_hdr_len = 20
        checksum = 0xffff
        gre_caplen = gre_eth_hdr_len + gre_ip_hdr_len + pkt_data_len
        gre_length =  gre_caplen
        if length > caplen:
            gre_length =  gre_eth_hdr_len + gre_ip_hdr_len + length

        frag_and_offset = (first_frag_pkt_data_len + 8) / 8  # offset + gre 8 bytes

        struct.pack_into("<IIII", self.export_bytearray, self.export_bytearray_pos, ts_sec, ts_usec, gre_caplen, gre_length)
        self.export_bytearray_pos += 16
        struct.pack_into(">HIHIBB", self.export_bytearray, self.export_bytearray_pos, 0,0,0,0, 0x08, 0x00)
        self.export_bytearray_pos += gre_eth_hdr_len
        struct.pack_into(">BBHHHBBHII", self.export_bytearray, self.export_bytearray_pos, 0x45, 0, gre_ip_hdr_len + pkt_data_len,
                         ipid, frag_and_offset, 0x40, 0x2f, checksum, keybit, 0x7F000001)
        self.export_bytearray_pos += gre_ip_hdr_len
        if pkt_data_len > 0:
            struct.pack_into("!%ds"%(pkt_data_len), self.export_bytearray, self.export_bytearray_pos, pkt_data)
            self.export_bytearray_pos += pkt_data_len


    def get_ipid_from_map(self, keybit):
        ipid = 0
        if keybit in self.keybit_ipid_map:
            ipid = self.keybit_ipid_map[keybit]
            ipid = (ipid + 1) % 65535
        self.keybit_ipid_map[keybit] = ipid
        return ipid


    def write_buf_to_pcap(self, pcapfile):
        pcapfile.write(self.export_bytearray[:self.export_bytearray_pos])
        self.export_bytearray_pos = 0


    def process_data(self, pkts_list):
        span_time = self.config["span_time"]
        global grekey_file_info
        # export to pcap
        for p in pkts_list:
            (ts_sec_and_usec,  caplen, length, keybit, pkt_data_len, pkt_data) = p
            ts_sec = ts_sec_and_usec / 1000000
            ts_usec = ts_sec_and_usec % 1000000
            if grekey_file_info != None:
                suffix_id, pcap_ts, pcapfile = grekey_file_info
                if (ts_sec // span_time) != (pcap_ts // span_time):  # need to rotate to new pcap file
                    self.write_buf_to_pcap(pcapfile)
                    pcapfile = get_pcapfile(self.config, ts_sec)
            else:
                pcapfile = get_pcapfile(self.config, ts_sec)
            buff_is_full = self.construct_pkt_bytes(ts_sec, ts_usec, caplen, length, keybit, pkt_data_len, pkt_data)
            if buff_is_full:
                pcapfile = get_pcapfile(self.config, ts_sec)
                self.write_buf_to_pcap(pcapfile)


    def sort_and_export_pkts(self):
        self.evict_pkts_list.sort(key=takeFirst)
        if self.pkt_evict_ts_checkpoint == 0:
            self.pkt_evict_ts_checkpoint = self.first_pkt_ts_time + self.PKT_EVICT_INTERVAL - self.PKT_EVICT_TS_TIMEOUT
        else:
            self.update_next_checkpoint()
        pkts_list = []
        pkts_count = len(self.evict_pkts_list)
        lasti = 0
        while lasti < pkts_count:
            p = self.evict_pkts_list[lasti]
            ts_sec = p[0] / 1000000
            if ts_sec >= self.pkt_evict_ts_checkpoint:
                break
            lasti += 1
        pkts_list = self.evict_pkts_list[:lasti]
        if lasti > 0:
            self.evict_pkts_list = self.evict_pkts_list[lasti:]

        export_pkts_count = len(pkts_list)
        left_pkts_count = len(self.evict_pkts_list)
        if pkts_list:
            self.process_data(pkts_list)
        return export_pkts_count, left_pkts_count


    def get_next_checkpoint(self):
        ts_advance = 0
        if self.new_realworld_ts_pkt_ts_diff < self.min_realworld_ts_pkt_ts_diff:
            ts_advance = self.min_realworld_ts_pkt_ts_diff - self.new_realworld_ts_pkt_ts_diff
        return self.pkt_evict_ts_checkpoint + self.PKT_EVICT_INTERVAL + ts_advance


    def update_next_checkpoint(self):
        self.pkt_evict_ts_checkpoint = self.get_next_checkpoint()
        if self.new_realworld_ts_pkt_ts_diff < self.min_realworld_ts_pkt_ts_diff:
            print("id: %d, new min realworld pkt ts diff: %ds"%(self.config['base_suffixid'], self.new_realworld_ts_pkt_ts_diff))
            self.min_realworld_ts_pkt_ts_diff = self.new_realworld_ts_pkt_ts_diff


    def evict_pkts(self, realworld_time_sec_and_usec, fqueue_full_drop):
        self.evict_num += 1
        if self.first_pkt_ts_time == 0:
            return
        timeout_drop_pkts = 0
        evicted_msg_count = 0
        total_msg_count = 0
        to_del_ts = []
        next_checkpoint = self.get_next_checkpoint()
        for ts, msg_list in self.msg_dict.items():
            total_msg_count += len(msg_list)
            if ts < next_checkpoint:
                evicted_msg_count += len(msg_list)
                for msg in msg_list:
                    timeout_drop_pkts += self.unpack_msgpkts_to_evict(msg)
                to_del_ts.append(ts)
        for ts in to_del_ts:
            del self.msg_dict[ts]
        self.gen_heartbeat()
        export_pkts_count, left_pkts_count = self.sort_and_export_pkts()
        now = time.time()
        nowstr = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now))
        print("[%s] id: %d, used: %.2fs, msg %d/%d: %d/%d evicted, export/leftPkts: %d/%d, timeout/frontq/totalDropPkts: %d/%d/%d"%(
            nowstr, self.config["base_suffixid"], now - realworld_time_sec_and_usec, evicted_msg_count, total_msg_count, len(to_del_ts), len(to_del_ts) + len(self.msg_dict),
            export_pkts_count, left_pkts_count, timeout_drop_pkts, fqueue_full_drop, self.total_drop_pkts))
        sys.stdout.flush()


    def gen_heartbeat(self):
        if self.first_pkt_ts_time != 0:
            if self.last_heartbeat_ts == 0:
                self.last_heartbeat_ts = self.first_pkt_ts_time
            next_checkpoint = self.get_next_checkpoint()
            while self.last_heartbeat_ts < next_checkpoint:
                self.last_heartbeat_ts += 1
                pkt_info = (self.last_heartbeat_ts*1000000, 0, 0, 0, 0, [])
                self.evict_pkts_list.append(pkt_info)


    def parse_messages(self, messages):
        header_size = 8
        realworld_time_sec_and_usec = time.time()
        realworld_time = int(realworld_time_sec_and_usec)
        if self.first_msg_realworld_time == 0:
            self.first_msg_realworld_time = realworld_time
        fqueue_full_drop = 0
        if messages:
            for message in messages:
                version, pkt_num, keybit = struct.unpack(">HHI", message[:header_size])
                if version != 1:
                    return
                pkt_pos = header_size
                if pkt_num > 0:
                    pkt_data_len, pkt_ts_time = struct.unpack(">HI", message[pkt_pos:pkt_pos+6])
                    if self.first_pkt_ts_time == 0:
                        self.first_pkt_realworld_time = realworld_time
                        self.first_pkt_ts_time = pkt_ts_time
                        self.min_realworld_ts_pkt_ts_diff = realworld_time - pkt_ts_time
                        print("first_pkt_realworld_time: %d, first_pkt_ts_time: %d, diff: %ds"%(realworld_time, self.first_pkt_ts_time, self.min_realworld_ts_pkt_ts_diff))
                    self.new_realworld_ts_pkt_ts_diff = realworld_time - pkt_ts_time
                    if pkt_ts_time in self.msg_dict:
                        self.msg_dict[pkt_ts_time].append(message)
                    else:
                        if len(self.msg_dict) > self.PKT_EVICT_TS_TIMEOUT + self.PKT_EVICT_INTERVAL + 20:
                            fqueue_full_drop += pkt_num
                            self.total_drop_pkts += pkt_num
                        else:
                            self.msg_dict[pkt_ts_time] = [message]
        if realworld_time >= self.first_msg_realworld_time + self.PKT_EVICT_INTERVAL * (self.evict_num + 1):
            self.evict_pkts(realworld_time_sec_and_usec, fqueue_full_drop)


def recv_msg_to_parse(batch_pkts_handler, socket):
    messages = []
    try:
        while True:
            message = socket.recv(flags=zmq.NOBLOCK)
            messages.append(message)
    except zmq.error.Again as _e:
        if not messages and not batch_pkts_handler.is_working_busy():
            time.sleep(0.01)
    batch_pkts_handler.parse_messages(messages)

def server_loop_imp(config):
    context = zmq.Context()
    socket = context.socket(zmq.PULL)
    socket.setsockopt(zmq.RCVTIMEO, 1000)
    socket.setsockopt(zmq.RCVHWM, 2000 * 1000)
    socket.setsockopt(zmq.SNDHWM, 2000 * 1000)
    if config["total_workers"] == 1:
        socket.bind("tcp://*:%d"%(config["zmq_port"]))
    else:
        socket.connect("tcp://127.0.0.1:%d"%(config["zmq_port"]))
    batch_pkts_handler = BatchPktsHandler(config)
    while True:
        try:
            recv_msg_to_parse(batch_pkts_handler, socket)
        except KeyboardInterrupt:
            eprint("KeyboardInterrupt")
            raise
        except Exception as e:
            eprint(e)
            track = traceback.format_exc()
            eprint(track)
            raise
        except struct.error as se:
            eprint(se)
        except:
            eprint("Unexpected error")
            raise


def server_loop(port, file_template, span_time, total_workers, frag_offset, base_suffixid):
    config = { "zmq_port": port, "file_template": file_template, "span_time": span_time,
               "total_workers": total_workers, "frag_offset": frag_offset, "base_suffixid": base_suffixid }
    server_loop_imp(config)


def check_need_terminate(workers):
    need_term = False
    for w in workers:
        if not w.is_alive():
            need_term = True
    if need_term:
        eprint("Fatal error: at least one worker process exited")
        for w in workers:
            if w.is_alive():
                w.terminate()
        sys.exit(-1)


def dispatch_loop(config):
    context = zmq.Context()
    front_socket = context.socket(zmq.PULL)
    front_socket.setsockopt(zmq.RCVTIMEO, 1000)
    front_socket.setsockopt(zmq.RCVHWM, 2000 * 1000)
    front_socket.setsockopt(zmq.SNDHWM, 2000 * 1000)
    front_socket.bind("tcp://*:%d"%(config["zmq_port"]))

    backend_port = config["zmq_port"] + 1
    backend_socket = context.socket(zmq.PUSH)
    backend_socket.setsockopt(zmq.SNDTIMEO, 1000)
    backend_socket.setsockopt(zmq.RCVHWM, 2000 * 1000)
    backend_socket.setsockopt(zmq.SNDHWM, 2000 * 1000)
    backend_socket.bind("tcp://127.0.0.1:%d"%(backend_port))
    workers = []
    for i in range(config["total_workers"]):
        w = Process(target=server_loop, args=(backend_port, config["file_template"], config["span_time"], config["total_workers"], config["frag_offset"], i))
        workers.append(w)
        w.start()

    while True:
        try:
            message = None
            try:
                message = front_socket.recv()
            except zmq.error.Again:
                check_need_terminate(workers)
            if message is None:
                continue
            while True:
                try:
                    backend_socket.send(message)
                except zmq.error.Again as _e:
                    check_need_terminate(workers)
                break
        except KeyboardInterrupt:
            eprint("KeyboardInterrupt")
            raise
        except Exception as e:
            eprint(e)
            track = traceback.format_exc()
            eprint(track)
            raise
        except:
            eprint("Unexpected error")
            raise


def usage():
    print(
"""Usage:
python recvzmq.py [--span_time seconds] -z port_num -t /path/file_template
-z or --zmq_port:\tzmq bind port
-t or --file_template:\tfile template. Examle: /opt/pcap_cache/nic0/%Y%m%d%H%M%S
-s or --span_time:\tpcap span time interval. Default: 15, Unit: seconds.
-a or --total_workers:\ttotal worker process count of recvzmq. Default 1.
-g or --frag_offset:\tspecify ip fragment offset( <= 65535). Default 64000
-v or --version:\tversion info
-h or --help:\t\thelp message
""")


def parse_args(cfg_dict):
    if len(sys.argv) == 1:
        usage()
        sys.exit()
    try:
        options, args = getopt.getopt(sys.argv[1:], "hvz:t:s:a:b:g:",
                                      ["help", "version", "zmq_port=", "file_template=", "span_time=", "total_workers=", "base_suffixid=", "frag_offset="])
    except getopt.GetoptError as e:
        eprint(e)
        sys.exit(-1)

    for name, value in options:
        if name in ("-h", "--help"):
            usage()
            sys.exit()
        elif name in ("-v", "--version"):
            print('recvzmq version 1.3.0')
            sys.exit()
        elif name in ("-z", "--zmq_port"):
            cfg_dict["zmq_port"] = int(value)
        elif name in ("-t", "--file_template"):
            cfg_dict["file_template"] = value
        elif name in ("-s", "--span_time"):
            cfg_dict["span_time"] = int(value)
        elif name in ("-a", "--total_workers"):
            cfg_dict["total_workers"] = int(value)
        elif name in ("-b", "--base_suffixid"):
            cfg_dict["base_suffixid"] = int(value)
        elif name in ("-g", "--frag_offset"):
            cfg_dict["frag_offset"] = 65535 if int(value) > 65535 else int(value)
    if "zmq_port" not in cfg_dict:
        eprint("require param: -z zmq_port")
        sys.exit(-1)
    if "file_template" not in cfg_dict:
        eprint("require param: -t /path/file_template/%Y%m%d/%Y%m%d%H/%Y%m%d%H%M%S")
        sys.exit(-1)

config = {"span_time": 15, "total_workers": 1, "base_suffixid": 0, "frag_offset": 64000}
parse_args(config)
if config["total_workers"] == 1:
    server_loop_imp(config)
else:
    dispatch_loop(config)

