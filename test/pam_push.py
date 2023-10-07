# coding:utf-8
import json
import os
from flask import Flask, request

app = Flask(__name__)

#http://0.0.0.0:9022/api/v1/daemons
__base_url = '/api/v1/'
__agent_nic = 'eth0'
__daemon = {}

def resp_with_error(sc, code, message):
    rep = {
        'code': code,
        'message': message
    }
    rep_js = json.dumps(rep)
    return rep_js, sc


@app.route(__base_url + 'daemons', methods=['POST'])
def post_daemons():
    global __daemon

    req_data = request.get_data()
    req = json.loads(req_data.decode("utf-8"))
    if not req.has_key('id'):
        req['id'] = 0
    if not req.has_key(''):
        req['syncMode'] = 'push'
    __daemon = req
    rep_js = json.dumps(req)
    return rep_js, 200

if __name__ == '__main__':
    global __agent_nic, __gre_remote_ip

    if os.environ.has_key('TEST_NIC'):
        __agent_nic = str(os.environ['TEST_NIC'])
    app.run(debug=True, host='127.0.0.1', port=9090)
