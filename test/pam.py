# coding:utf-8
import json
import thread
import time
import requests
import os
from flask import Flask, request

app = Flask(__name__)

#http://0.0.0.0:9022/api/v1/daemons
__base_url = '/api/v1/'
__agent_nic = 'ens33'
__daemon = {}
__sync_cnts = 0
__gre_remote_ip = '147.147.147.147'

def pull_to_push(delay, step):
    global __daemon, __agent_nic

    time.sleep(delay)

    service = str(__daemon['service'])

    # update agent stop
    for idx in [0, 1]:
        agent = __daemon['agents'][idx]
        req_js = json.dumps(agent)
        resp = requests.post(service + '/api/v1/daemon/agents/' + str(idx) + '?action=stop', req_js)

        assert(resp.status_code == 200)
        resp_js = resp.json()
        assert(resp_js['status'] == 'inactive')
        __daemon['agents'][idx] = resp_js
        #print(json.dumps(__daemon))
        time.sleep(step)


    # update agent start
    for idx in [0, 1]:
        agent = __daemon['agents'][idx]
        req_js = json.dumps(agent)
        resp = requests.post(service + '/api/v1/daemon/agents/' + str(idx) + '?action=start', req_js)

        assert(resp.status_code == 200)
        resp_js = resp.json()
        assert(resp_js['status'] == 'active')
        __daemon['agents'][idx] = resp_js
        #print(json.dumps(__daemon))
        time.sleep(step)

    agent_ip = os.popen('ifconfig ' + __agent_nic + ' | grep \"inet \" | awk \'{print $2}\'').read().strip()

    # rewrite pcap
    os.system('tcpprep -c 58.49.108.208/32 -i http_sample.pcap -o http_sample.cache')
    os.system('tcprewrite --endpoints=58.49.108.208:' + agent_ip + ' --infile=http_sample.pcap --outfile=http_sample_rewrite.pcap --skipbroadcast --cachefile=http_sample.cache')
    os.system('rm -rf http_sample.cache')
    # play pcap
    os.system('tcpdump -i ' + __agent_nic + ' ip proto 47 and ip dst ' + __gre_remote_ip + ' -w pa_gre_dump.pcap &')
    os.system('tcpreplay -i ' + __agent_nic + ' -p 100 -l 1 http_sample_rewrite.pcap')
    time.sleep(step)
    os.system('rm -rf http_sample_rewrite.cache')
    time.sleep(delay)
    os.system('killall tcpdump')
    assert(os.popen('tcpreplay -i ' + __agent_nic + ' -p 400 -l 1 pa_gre_dump.pcap | grep \"Successful packets\" | awk \'{print $3}\'').read().strip() == '224')
    #os.system('rm -rf http_sample_rewrite.pcap')

    # get agents
    resp = requests.get(service + '/api/v1/daemon/agents')
    assert(resp.status_code == 200)
    __daemon['agents'] = resp.json()
    #print(json.dumps(__daemon))
    time.sleep(step)

    # get status
    resp = requests.get(service + '/api/v1/daemon')
    assert(resp.status_code == 200)
    __daemon = resp.json()
    assert(__daemon['agents'][0]['data']['packetChannelMetrics']['capPackets'] == 82)
    assert(__daemon['agents'][1]['data']['packetChannelMetrics']['capPackets'] == 142)
    #print(json.dumps(__daemon))
    time.sleep(step)

    # killall agents daemon
    os.system('killall agentdaemon')
    os.system('killall pktminerg')
    pam_pid = os.popen('netstat -apn | grep 8081 | awk \'{print $7}\' | awk -F\/ \'{print $1}\'').read().strip()
    os.system('kill ' + pam_pid)

def resp_with_error(sc, code, message):
    rep = {
        'code': code,
        'message': message
    }
    rep_js = json.dumps(rep)
    return rep_js, sc

def add_agent(req, id, key, nic, filter):
    global __daemon, __gre_remote_ip

    if((not req.has_key('agents')) or (len(req['agents']) == 0)):
        req['agents'] = []
    agents = req['agents']
    agent = {
        "id": id,
        "agentType": "PA",
        "data": {
            "serviceTag": key,
            "startup": "",
            "bpf": filter,
            "cpuLimit": 0.1, #10%cpu
            "memLimit": 40, #40M
            "buffLimit": 4194304, #4M
            "packetChannelType": "GRE",
            "packetChannelKey": key,
            "packetChannel": {
                "address": __gre_remote_ip
            }
        }
    }
    for interface in __daemon['networkInterfaces']:
        if interface['name'] == nic:
            agent['data']['networkInterface'] = interface
    agents.append(agent)

@app.route(__base_url + 'daemons', methods=['POST'])
def post_daemons():
    global __daemon

    req_data = request.get_data()
    req = json.loads(req_data.decode("utf-8"))
    if not req.has_key('id'):
        req['id'] = 0
    if not req.has_key(''):
        req['syncMode'] = 'pull'
    __daemon = req
    rep_js = json.dumps(req)
    return rep_js, 200

@app.route(__base_url + 'daemons/sync', methods=['POST'])
def post_daemons_sync():
    global __daemon, __sync_cnts

    req_data = request.get_data()
    req = json.loads(req_data.decode("utf-8"))

    if not (int(req['id']) == int(__daemon['id'])):
        return resp_with_error(404, 404, "daemon id not found")

    if not (req['syncMode'] == 'pull'):
        return resp_with_error(404, 404, "syncMode not pull")

    if((not req.has_key('agents')) or (len(req['agents']) == 0)):
        add_agent(req, 0, 29, 'ens33', 'tcp port 15977') #82pkts
        add_agent(req, 1, 30, 'ens33', 'tcp port 15992')#142pkts

    __daemon = req
    __sync_cnts = __sync_cnts + 1
    if (__sync_cnts % 2) == 0:
        __daemon['syncMode'] = 'push'
        thread.start_new_thread(pull_to_push, (5, 1))

    rep_js = json.dumps(req)
    return rep_js, 200

if __name__ == '__main__':
    global __agent_nic, __gre_remote_ip

    if os.environ.has_key('TEST_NIC'):
        __agent_nic = str(os.environ['TEST_NIC'])
    if os.environ.has_key('TEST_RIP'):
        __gre_remote_ip = str(os.environ['TEST_RIP'])

    app.run(debug=True, host='0.0.0.0', port=8081)
