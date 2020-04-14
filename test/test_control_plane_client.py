#!/bin/env python
# -*- coding: utf-8 -*-


import zmq
import time
from struct import pack, unpack, calcsize
from docopt import docopt
from IPy import IP




PKT_SERVER = 'tcp://127.0.0.1:5556'
TIME_OUT = 5000

DIAG_TYPE_SLICE = 0
DIAG_TYPE_FILTER = 1
#DIAG_TYPE_DEEP_SLICE = 2
DIAG_TYPE_BTR = 3

# msg_item = self.msg_map["%s_%s" % (self._opt, self._msg_operand)]
message = pack('=iiii', 0x504D3230, 0x10,
               0x0001,
               0x0f0f)
socket = zmq.Context().socket(zmq.REQ)
socket.setsockopt(zmq.LINGER, 0)
poll_obj = zmq.Poller()
poll_obj.register(socket, zmq.POLLIN)
socket.connect(PKT_SERVER)
socket.send(message)
event = dict(poll_obj.poll(TIME_OUT))
ret = (0x504D3230, 0x0C, 0xFFFF, 0x0)
if event.get(socket) == zmq.POLLIN :
    response = socket.recv()
    ret = unpack('=iiiiiiiiiiii',
                  response[0: 48])

print ret
socket.close()

