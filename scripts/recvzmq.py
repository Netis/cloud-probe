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
import threading

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
    file_path = "%s_%d_%d"%(file_path_str, config["total_clients"], suffix_id)
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


class BatchPktsHandler(threading.Thread):

    def __init__(self, config):
        threading.Thread.__init__(self)

        self.PKT_EVICT_TS_TIMEOUT = 5
        self.PKT_EVICT_INTERVAL = 1
        self.PKT_EVICT_BUFF_SIZE = 1024*1024

        self.config = config
        self.first_msg_realworld_time = 0
        self.first_pkt_realworld_time = 0
        self.first_pkt_ts_time = 0
        self.last_heartbeat_ts = 0
        self.evict_num = 0
        self.pkt_evict_ts_checkpoint = 0
        self.msg_dict = {}
        self.evict_pkts_list = []
        self.export_bytearray = bytearray(self.PKT_EVICT_BUFF_SIZE)
        self.export_bytearray_pos = 0
        self.total_drop_pkts = 0

        self.export_cond = threading.Condition()
        self.export_queue = deque()
        self.exitFlag = False


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
        checksum = 0xffff
        gre_caplen = gre_eth_hdr_len + gre_ip_hdr_len + gre_hdr_len + pkt_data_len
        gre_length =  gre_caplen
        if length > caplen:
            gre_length =  gre_eth_hdr_len + gre_ip_hdr_len + gre_hdr_len + length

        struct.pack_into("<IIII", self.export_bytearray, self.export_bytearray_pos, ts_sec, ts_usec, gre_caplen, gre_length)
        self.export_bytearray_pos += 16
        struct.pack_into(">HIHIBB", self.export_bytearray, self.export_bytearray_pos, 0,0,0,0, 0x08, 0x00)
        self.export_bytearray_pos += gre_eth_hdr_len
        struct.pack_into(">BBHHBBBBHII", self.export_bytearray, self.export_bytearray_pos, 0x45, 0, gre_ip_hdr_len + gre_hdr_len + pkt_data_len,
                         0, 0x40, 0, 0x40, 0x2f, checksum, 0x7F000001, 0x7F000001)
        self.export_bytearray_pos += gre_ip_hdr_len
        struct.pack_into(">HHI", self.export_bytearray, self.export_bytearray_pos, 0x2000, 0x6558, keybit)
        self.export_bytearray_pos += gre_hdr_len
        if pkt_data_len > 0:
            struct.pack_into("!%ds"%(pkt_data_len), self.export_bytearray, self.export_bytearray_pos, pkt_data)
            self.export_bytearray_pos += pkt_data_len

        buff_is_full = False
        if self.export_bytearray_pos >= self.PKT_EVICT_BUFF_SIZE - 65536:
            buff_is_full = True
        return buff_is_full


    def write_buf_to_pcap(self, pcapfile):
        pcapfile.write(self.export_bytearray[:self.export_bytearray_pos])
        self.export_bytearray_pos = 0


    def stop_running(self):
        self.exitFlag = True
        self.export_cond.acquire()
        self.export_cond.notify()
        self.export_cond.release()

    def run(self):
        while not self.exitFlag:
            pkts_list = []
            self.export_cond.acquire()
            while len(self.export_queue) == 0:  # q is empty
                self.export_cond.wait()
                if self.exitFlag:
                    return
            pkts_list = self.export_queue.popleft()
            self.export_cond.release()

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


    def producer_fillqueue_sync(self, pkts_list):
        qfull_drop_pkts = 0

        self.export_cond.acquire()
        if len(self.export_queue) >= 30:
            qfull_drop_pkts = len(pkts_list)
            self.total_drop_pkts += qfull_drop_pkts
        else:
            self.export_queue.append(pkts_list)
        self.export_cond.notify()
        self.export_cond.release()

        return qfull_drop_pkts

    def sort_and_export_pkts(self):
        self.evict_pkts_list.sort(key=lambda x: x[0])
        if self.pkt_evict_ts_checkpoint == 0:
            self.pkt_evict_ts_checkpoint = self.first_pkt_ts_time + self.PKT_EVICT_INTERVAL - self.PKT_EVICT_TS_TIMEOUT
        else:
            self.pkt_evict_ts_checkpoint += self.PKT_EVICT_INTERVAL
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

        qfull_drop_pkts = 0
        export_queue_len = len(self.export_queue)
        export_pkts_count = len(pkts_list)
        left_pkts_count = len(self.evict_pkts_list)
        if pkts_list:
            qfull_drop_pkts= self.producer_fillqueue_sync(pkts_list)
        return qfull_drop_pkts, export_pkts_count, left_pkts_count, export_queue_len


    def evict_pkts(self):
        self.evict_num += 1
        if self.first_pkt_ts_time == 0:
            return
        timeout_drop_pkts = 0
        evicted_msg_count = 0
        total_msg_count = 0
        to_del_ts = []
        for ts, msg_list in self.msg_dict.items():
            total_msg_count += len(msg_list)
            if ts < self.pkt_evict_ts_checkpoint + self.PKT_EVICT_INTERVAL: #TODO: diff
                evicted_msg_count += len(msg_list)
                for msg in msg_list:
                    timeout_drop_pkts += self.unpack_msgpkts_to_evict(msg)
                to_del_ts.append(ts)
        for ts in to_del_ts:
            del self.msg_dict[ts]
        qfull_drop_pkts, export_pkts_count, left_pkts_count, export_queue_len = self.sort_and_export_pkts()
        print("Msg %d/%d evicted, exportPkts/leftPkts: %d/%d, timeout/qfull/totalDropPkts: %d/%d/%d, queueLen: %d"%(
            evicted_msg_count, total_msg_count, export_pkts_count, left_pkts_count,
            timeout_drop_pkts, qfull_drop_pkts, self.total_drop_pkts, export_queue_len))


    def gen_heartbeat(self, realworld_time):
        if self.first_pkt_ts_time != 0:
            if self.last_heartbeat_ts == 0:
                self.last_heartbeat_ts = self.first_pkt_ts_time
            expect_count = realworld_time - self.first_pkt_realworld_time
            count = self.last_heartbeat_ts - self.first_pkt_ts_time
            while count < expect_count:
                self.last_heartbeat_ts += 1
                pkt_info = (self.last_heartbeat_ts*1000000, 0, 0, 0, 0, [])
                self.evict_pkts_list.append(pkt_info)
                count += 1


    def parse_message(self, message):
        header_size = 8
        realworld_time_sec_and_usec = int(round(time.time()*1000000))
        realworld_time = realworld_time_sec_and_usec / 1000000
        if self.first_msg_realworld_time == 0:
            self.first_msg_realworld_time = realworld_time
        if message is not None:
            version, pkt_num, keybit = struct.unpack(">HHI", message[:header_size])
            if version != 1:
                return
            pkt_pos = header_size
            if pkt_num > 0:
                pkt_data_len, pkt_ts_time = struct.unpack(">HI", message[pkt_pos:pkt_pos+6])
                if self.first_pkt_ts_time == 0:
                    self.first_pkt_realworld_time = realworld_time
                    self.first_pkt_ts_time = pkt_ts_time
                    print("first_pkt_realworld_time: %d, first_pkt_ts_time: %d"%(realworld_time, self.first_pkt_ts_time))
                if pkt_ts_time in self.msg_dict:
                    self.msg_dict[pkt_ts_time].append(message)
                else:
                    self.msg_dict[pkt_ts_time] = [message]
        self.gen_heartbeat(realworld_time)
        if realworld_time >= self.first_msg_realworld_time + self.PKT_EVICT_INTERVAL * (self.evict_num + 1):
            self.evict_pkts()


def recv_msg_to_parse(batch_pkts_handler, socket):
    message = None
    try:
        message = socket.recv()
    except zmq.error.Again as _e:
        pass
    batch_pkts_handler.parse_message(message)

def server_loop_imp(config):
    context = zmq.Context()
    socket = context.socket(zmq.PULL)
    socket.setsockopt(zmq.RCVTIMEO, 1000)
    socket.bind("tcp://*:%d"%(config["zmq_port"]))
    #socket.connect("tcp://127.0.0.1:%d"%(config["zmq_port"]))
    batch_pkts_handler = BatchPktsHandler(config)
    batch_pkts_handler.start()
    while True:
        try:
            recv_msg_to_parse(batch_pkts_handler, socket)
        except KeyboardInterrupt:
            eprint("KeyboardInterrupt")
            batch_pkts_handler.stop_running()
            batch_pkts_handler.join()
            raise
        except Exception as e:
            eprint(e)
            track = traceback.format_exc()
            eprint(track)
        except struct.error as se:
            eprint(se)
        except:
            eprint("Unexpected error")


def server_loop(port, file_template, span_time, total_clients, base_suffixid):
    config = { "zmq_port": port, "file_template": file_template, "span_time": span_time,
               "total_clients": total_clients, "base_suffixid": base_suffixid }
    server_loop_imp(config)


def dispatch_loop(config):
    context = zmq.Context()
    front_socket = context.socket(zmq.PULL)
    front_socket.bind("tcp://*:%d"%(config["zmq_port"]))

    backend_port = config["zmq_port"] + 1
    backend_socket = context.socket(zmq.PUSH)
    backend_socket.bind("tcp://127.0.0.1:%d"%(backend_port))
    for i in range(config["total_clients"]):
        Process(target=server_loop, args=(backend_port, config["file_template"], config["span_time"], config["total_clients"], i)).start()

    while True:
        try:
            message = front_socket.recv()
            backend_socket.send(message)
        except KeyboardInterrupt:
            eprint("KeyboardInterrupt")
            raise
        except Exception as e:
            eprint(e)
            track = traceback.format_exc()
            eprint(track)
        except:
            eprint("Unexpected error")


def usage():
    print(
"""Usage:
python recvzmq.py [--span_time seconds] -z port_num -t /path/file_template
-z or --zmq_port:\tzmq bind port
-t or --file_template:\tfile template. Examle: /opt/pcap_cache/nic0/%Y%m%d%H%M%S
-s or --span_time:\tpcap span time interval. Default: 10, Unit: seconds.
-a or --total_clients:\ttotal clients count of all recvzmq processes. Default 1.
-v or --version:\tversion info
-h or --help:\t\thelp message
""")


def parse_args(cfg_dict):
    if len(sys.argv) == 1:
        usage()
        sys.exit()
    try:
        options, args = getopt.getopt(sys.argv[1:], "hvz:t:s:a:b:",
                                      ["help", "version", "zmq_port=", "file_template=", "span_time=", "total_clients=", "base_suffixid="])
    except getopt.GetoptError as e:
        eprint(e)
        sys.exit(-1)

    for name, value in options:
        if name in ("-h", "--help"):
            usage()
            sys.exit()
        elif name in ("-v", "--version"):
            print('recvzmq version 1.1.0')
            sys.exit()
        elif name in ("-z", "--zmq_port"):
            cfg_dict["zmq_port"] = int(value)
        elif name in ("-t", "--file_template"):
            cfg_dict["file_template"] = value
        elif name in ("-s", "--span_time"):
            cfg_dict["span_time"] = int(value)
        elif name in ("-a", "--total_clients"):
            cfg_dict["total_clients"] = int(value)
        elif name in ("-b", "--base_suffixid"):
            cfg_dict["base_suffixid"] = int(value)
    if "zmq_port" not in cfg_dict:
        eprint("require param: -z zmq_port")
        sys.exit(-1)
    if "file_template" not in cfg_dict:
        eprint("require param: -t /path/file_template/%Y%m%d/%Y%m%d%H/%Y%m%d%H%M%S")
        sys.exit(-1)

config = {"span_time": 10, "total_clients": 1, "base_suffixid": 0}
parse_args(config)
#dispatch_loop(config)
server_loop_imp(config)

