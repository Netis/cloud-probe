# coding:utf-8
import json
import thread
import time
import requests
import os
from unittest import TestCase
from flask import Flask, request

app = Flask(__name__)
#__test_case = TestCase()
#http://0.0.0.0:9022/api/v1/daemons
__base_url = '/api/v1/'
__agent_nic1 = 'ens33'
__agent_nic2 = 'ens32'
__daemon = {}
__sync_cnts = 0
__remote_ip1 = '147.147.147.147'
__remote_ip2 = '146.146.146.146'
__fp = open('err.log', 'a+')


def resp_with_error(sc, code, message):
    rep = {
        'code': code,
        'message': message
    }
    rep_js = json.dumps(rep)
    return rep_js, sc

def add_agent(req, id, key, filter):
    global __daemon, __remote_ip1, __remote_ip2, __agent_nic1, __agent_nic2

    req['agent'] = {
        "id": id,
        "agentType": "PA",
        "cpuLimit": 0.1, #10%cpu
        "memLimit": 40, #40M
        "packetAgentStrategies": [{
            "serviceTag": 1,
            "startup": "",
            'networkInterface': {
                "name" : __agent_nic1
            },
            "bpf": filter,
            "packetChannelType": "GRE",
            "address": __remote_ip1
        },
        {
            "serviceTag": 1,
            "startup": "",
            'networkInterface': {
                "name" : __agent_nic2
            },
            "bpf": filter,
            "packetChannelType": "VXLAN",
            "address": __remote_ip2
        }]
    }

@app.route(__base_url + 'daemons', methods=['POST'])
def post_daemons():
    global __daemon, __test_case, __fp

    req_data = request.get_data()
    req = json.loads(req_data.decode("utf-8"))
    if req['syncMode'] != 'pull':
        __fp.write("Err: mode is not pull in REG\n")
        return resp_with_error(404, 404, "syncMode not pull")

    if not req.has_key('networkInterfaces'):
        __fp.write("Err: no networkInterfaces in REG\n")
        return resp_with_error(404, 404, "no networkInterfaces in REG")

    rep_js = json.dumps(req)
    return rep_js, 200

@app.route(__base_url + 'daemons/sync', methods=['POST'])
def post_daemons_sync():
    global __daemon, __sync_cnts, __test_case, __fp

    req_data = request.get_data()
    req = json.loads(req_data.decode("utf-8"))

    hasNic1 = False
    hasNic2 = False
    for interface in req['networkInterfaces']:
        if interface['name'] == __agent_nic1:
            hasNic1 = True
        elif interface['name'] == __agent_nic2:
            hasNic2 = True
    if hasNic1 == False or hasNic2 == False:
        __fp.write("Err: no nic1 or nic 2 in sync\n")
        return resp_with_error(404, 404, "no nic1 or nic2 in REG")
  
    if __sync_cnts == 0:
        add_agent(req, 0, 29, 'host 10.1.1.10') #82pkts
    
    pro=os.system("ps -ef|grep pktminerg|grep -v grep")
    if pro == 0x100:
        __fp.write("Err: no pktminerg running\n")
        return resp_with_error(404, 404, "no pktminerg running")


    __daemon = req
    __sync_cnts = __sync_cnts + 1
    
    rep_js = json.dumps(req)
    if __sync_cnts == 1:
        __sync_cnts
        return rep_js, 200
    else:
        return rep_js, 304

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=9090)
