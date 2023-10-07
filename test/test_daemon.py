#!/usr/bin/env python
#  -*- coding: utf-8 -*-
import unittest
import time
import requests, json
import os

class DaemonTestCase(unittest.TestCase):

    def setUp(self):
        super(DaemonTestCase, self).setUp()
        #os.popen("../bin/agentdaemon -p 9090 2> server.log &")
        time.sleep(2)
        os.popen("../bin/agentdaemon -m http://127.0.0.1:9090/api/v1/daemons -l 1234,4678 -d push &")
        time.sleep(2)

    def tearDown(self):
        os.popen("killall agentdaemon")
        super(DaemonTestCase, self).tearDown()

    def test_start_update_stop_agnet(self):
        env_dist = os.environ
        nic = env_dist['TEST_NIC']
        channel_type = env_dist['TEST_CHANNEL_TYPE']
        bpf = 'tcp port 15977'
        rip = '10.1.1.33'
        # start agent
        request = json.dumps(
            {'id': 0, 'name': 'string', 'agentType': 'PA', 'status': 'active', 'startTime': '2020-04-14T07:50:26.096Z',
             'data': {'networkInterface': {'name': nic},
                      'bpf': bpf,
                      'packetChannelType': channel_type,
                      'packetChannel': {'address': rip}}})
        response = requests.post('http://127.0.0.1:9022/api/v1/daemon/agents', request)
        agent = response.json()
        self.assertEqual(201, response.status_code)
        self.assertEqual('active', agent['status'])
        self.assertTrue(agent['data']['networkInterface']['mtu'] > 1000)

        # update agent stop
        request = json.dumps(
            {'id': 0, 'name': 'string', 'agentType': 'PA',  'status': 'active', 'startTime': '2020-04-14T07:50:26.096Z',
             'data': {'networkInterface': {'name': nic},
                      'bpf': bpf,
                      'packetChannelType': channel_type,
                      'packetChannel': {'address': rip}}})

        response = requests.post('http://127.0.0.1:9022/api/v1/daemon/agents/0?action=stop', request)
        self.assertEqual(200, response.status_code)
        agent = response.json()
        self.assertEqual('inactive', agent['status'])

        request = json.dumps(
            {'id': 0, 'name': 'string', 'agentType': 'PA', 'status': 'active', 'startTime': '2020-04-14T07:50:26.096Z',
             'data': {'networkInterface': {'name': nic},
                      'bpf': bpf,
                      'packetChannelType': channel_type,
                      'packetChannel': {'address': rip}}})
        response = requests.post('http://127.0.0.1:9022/api/v1/daemon/agents/0?action=stop', request)
        self.assertEqual(200, response.status_code)
        agent = response.json()
        self.assertEqual('inactive', agent['status'])

        # update agent start
        request = json.dumps(
            {'id': 0, 'name': 'string', 'agentType': 'PA',  'status': 'active', 'startTime': '2020-04-14T07:50:26.096Z',
             'data': {'networkInterface': {'name': nic},
                      'bpf': bpf,
                      'packetChannelType': channel_type,
                      'packetChannel': {'address': rip}}})
        response = requests.post('http://127.0.0.1:9022/api/v1/daemon/agents/0?action=start', request)
        self.assertEqual(200, response.status_code)
        agent = response.json()
        self.assertEqual('active', agent['status'])

        request = json.dumps(
            {'id': 0, 'name': 'string', 'agentType': 'PA', 'status': 'active', 'startTime': '2020-04-14T07:50:26.096Z',
             'data': {'networkInterface': {'name': nic},
                      'bpf': bpf,
                      'packetChannelType': channel_type,
                      'packetChannel': {'address': rip}}})
        response = requests.post('http://127.0.0.1:9022/api/v1/daemon/agents/0?action=start', request)
        self.assertEqual(200, response.status_code)
        agent = response.json()
        self.assertEqual('active', agent['status'])

        # update agent restart
        request = json.dumps(
            {'id': 0, 'name': 'string', 'agentType': 'PA', 'status': 'active', 'startTime': '2020-04-14T07:50:26.096Z',
             'data': {'networkInterface': {'name': nic},
                      'bpf': bpf,
                      'packetChannelType': channel_type,
                      'packetChannel': {'address': rip}}})
        response = requests.post('http://127.0.0.1:9022/api/v1/daemon/agents/0', request)
        self.assertEqual(200, response.status_code)
        agent = response.json()
        self.assertEqual('active', agent['status'])

        # get daemon
        response = requests.get('http://127.0.0.1:9022/api/v1/daemon')
        self.assertEqual(200, response.status_code)
        daemon = response.json()
        print('Get Daemon:')
        print(json.dumps(daemon, sort_keys=True,  indent=4))
        #self.assertEqual(0, daemon['id']) 
        self.assertEqual('active',daemon['status'])
        self.assertTrue(len(daemon['networkInterfaces']) > 0 )

        # get agents list
        response = requests.get('http://127.0.0.1:9022/api/v1/daemon/agents')
        self.assertEqual(200, response.status_code)
        agents = response.json()
        print('Get Agents list:')
        print(json.dumps(agents, sort_keys=True,  indent=4))
        self.assertEqual(1, len(agents))
        self.assertEqual(1, agents[0]['id']) # id plus 1 after update
        self.assertEqual('active',agents[0]['status'])
        self.assertEqual(channel_type,agents[0]['data']['packetChannelType'])

        # get agents list again
        time.sleep(15)
        response = requests.get('http://127.0.0.1:9022/api/v1/daemon/agents')
        self.assertEqual(200, response.status_code)
        agents = response.json()
        print('Get Agents list:')
        print(json.dumps(agents, sort_keys=True, indent=4))
        self.assertEqual(1, len(agents))
        self.assertEqual(1, agents[0]['id'])  # id plus 1 after update
        self.assertEqual('active', agents[0]['status'])
        self.assertEqual(channel_type, agents[0]['data']['packetChannelType'])

        # get agent
        response = requests.get('http://127.0.0.1:9022/api/v1/daemon/agents/1')
        self.assertEqual(200, response.status_code)
        agent = response.json()
        self.assertEqual(1, agent['id'])
        self.assertEqual('active', agent['status'])
        self.assertEqual(channel_type, agent['data']['packetChannelType'])
        self.assertEqual(True, 'packetChannelMetrics' in agent['data'])

        # get non-exist agent
        response = requests.get('http://127.0.0.1:9022/api/v1/daemon/agents/2')
        self.assertEqual(404, response.status_code)

        # rewrite pcap
        agent_ip = os.popen('ifconfig ' + nic + ' | grep \"inet \" | awk \'{print $2}\' | awk -F: \'{print $2}\'').read().strip()
        #agent_ip = os.popen('ifconfig ' + nic + ' | grep \"inet \" | awk \'{print $2}\').read().strip()

        # rewrite pcap
        cmd = 'tcpprep -c 58.49.108.208/32 -i http_sample.pcap -o http_sample.cache'
        print(cmd)
        os.system(cmd)
        cmd = 'tcprewrite --endpoints=58.49.108.208:' + agent_ip + ' --infile=http_sample.pcap --outfile=http_sample_rewrite.pcap --skipbroadcast --cachefile=http_sample.cache'
        print(cmd)
        os.system(cmd)
        cmd = 'rm -rf http_sample.cache'
        print(cmd)
        os.system(cmd)

        # capture pkt
        #cmd = 'tcpdump -i ' + nic + ' ip proto 47 and ip dst ' + rip + ' -w pa_gre_dump.pcap &'
        #print(cmd)
        #os.system(cmd)

        # play pcap
        cmd = 'tcpreplay -i ' + nic + ' -p 100 -l 1 http_sample_rewrite.pcap'
        print(cmd)
        os.system(cmd)

        time.sleep(5)

        # check pkts
        cmd = 'killall tcpdump'
        print(cmd)
        os.system(cmd)
        #cmd = 'tcpreplay -i ' + nic + ' -p 400 -l 1 pa_gre_dump.pcap | grep \"Successful packets\" | awk \'{print $3}\''
        #print(cmd)
        #os.system('tcpreplay -i ' + nic + ' -p 400 -l 1 pa_gre_dump.pcap')
        #assert(os.popen(cmd).read().strip() == '82')

        # get agent
        response = requests.get('http://127.0.0.1:9022/api/v1/daemon/agents/1')
        self.assertEqual(200, response.status_code)
        agent = response.json()
        self.assertEqual(1, agent['id'])
        self.assertEqual('active', agent['status'])
        self.assertEqual(channel_type, agent['data']['packetChannelType'])
        self.assertEqual(True, 'packetChannelMetrics' in agent['data'])
        #self.assertEqual(82, int(agent['data']['packetChannelMetrics']['capPackets']))

        # delete agent
        response = requests.delete('http://127.0.0.1:9022/api/v1/daemon/agents/1')
        self.assertEqual(204, response.status_code)

        # register daemon
        if False:
            log = False
            with open("server.log") as f:
                lines = f.readlines()
                for line in lines:
                    if 'resource=/api/v1/daemons' not in line:
                        continue
                    log = True
                    daemon = json.loads(line.split('body=')[-1])
                    self.assertEqual('active', daemon['status'])
                    self.assertEqual('1234', daemon['labels'][0])
                    self.assertTrue(len(daemon['networkInterfaces']) > 0)

            self.assertEqual(True, log)

