
#include <iostream>
#include <string>
#include <cstring>
#include <chrono>
#include <thread>

#include "agent_status.h"
#include "agent_control_plane.h"


AgentControlPlane::AgentControlPlane():_zmq_port(DEFAULT_ZMQ_SERVER_PORT), 
        _zmq_context(DEFAULT_ZMQ_IO_THREAD), _zmq_socket(_zmq_context, ZMQ_REP), _tid(0) {

}

AgentControlPlane::AgentControlPlane(int zmq_port):_zmq_port(zmq_port), 
        _zmq_context(DEFAULT_ZMQ_IO_THREAD), _zmq_socket(_zmq_context, ZMQ_REP), _tid(0) {

}

AgentControlPlane::~AgentControlPlane() {    
    if (_tid != 0) {
        close_msg_server();
    }
    _tid = 0;
}



int AgentControlPlane::init_msg_server() {
    
    int32_t err = pthread_attr_init(&_attr);
    if (err != 0) {
        std::cerr << "[pktminerg] pthread_attr_init failed" << std::endl;
        return 1;
    }

    err = pthread_attr_setdetachstate(&_attr, PTHREAD_CREATE_DETACHED);
    if (0 == err) {
        err = pthread_create(&_tid, &_attr, run, (void*)this);
        if (err) {
            std::cerr << "[pktminerg] pthread_create failed" << std::endl;
        }
    }
    pthread_attr_destroy(&_attr);
    std::cout << "[pktminerg] daemon zmq server init fnished. tid = " << _tid << std::endl;
    
    return 0;
}

int AgentControlPlane::close_msg_server() {    
    if (pthread_cancel(_tid)) {
        std::cerr << "[pktminerg] pthread_cancel failed" << std::endl;
    }
    _tid = 0;
    return 0;
}


void* AgentControlPlane::run(void* inst) {
    if (!inst) {
        std::cerr << "[pktminerg] msg server routine: void handle" << std::endl;
        return nullptr;
    }
    AgentControlPlane* serv = static_cast<AgentControlPlane*>(inst);

    char zmq_addr[32] = "tcp://*:";
    std::string port = std::to_string(serv->_zmq_port);
    serv->_zmq_socket.bind(std::strcat(zmq_addr, port.c_str()));

    char recv_string[sizeof(msg_t)];
    msg_t pkt_req_msg, pkt_res_msg;

    pthread_cleanup_push(on_destroy, inst);

    while (true) {
        pthread_testcancel();

        memset(&pkt_req_msg, 0, sizeof(msg_t));
        memset(&pkt_res_msg, 0, sizeof(msg_t));
        memset(recv_string, 0, sizeof(msg_t));

        zmq::message_t msg_recv;        
        zmq::recv_result_t recv_ret = {};
        recv_ret = serv->_zmq_socket.recv(msg_recv, zmq::recv_flags::dontwait);
        if (!recv_ret) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            continue;
        }

        size_t zmq_recv_size = msg_recv.size();
        if (zmq_recv_size <= sizeof(recv_string)) {
            memcpy(recv_string, msg_recv.data(), zmq_recv_size);
        }

        serv->msg_req_process(recv_string, zmq_recv_size, &pkt_req_msg);
        serv->msg_rsp_process(&pkt_req_msg, &pkt_res_msg);

        // Send Response
        zmq::send_result_t send_ret = {};
        zmq::message_t msg_send(&pkt_res_msg, sizeof(msg_t), NULL);
        send_ret = serv->_zmq_socket.send(msg_send, zmq::send_flags::none);

        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }


    pthread_cleanup_pop(0);
    pthread_exit((void*) 0);
    return nullptr;
}




void AgentControlPlane::on_destroy(void* inst) {
    
}



int AgentControlPlane::msg_req_process(const char* buf, size_t size, msg_t* req_msg) {
    /* check size */
    if (size > (sizeof(msg_t))) {
        std::cerr << "[pktminerg] Err, too long msg size:" << size << std::endl;
        return -1;
    }

    /* construct msg */
    memcpy(req_msg, buf, size);

    if (size < (sizeof(msg_t) - MAX_MSG_CONTENT_LENGTH)) {
        std::cerr << "[pktminerg] Err, invalid msg size:" << size << std::endl;
        return -1;
    }

    /* check magic */
    if (req_msg->magic != MSG_MAGIC_NUMBER) {
        std::cerr << "[pktminerg] Err, invalid msg magic number:" << req_msg->magic << std::endl;
        return -1;
    }

    /* check action */
    if (req_msg->action >= MSG_ACTION_REQ_MAX) {
        std::cerr << "[pktminerg] Err, invalid action request:" << req_msg->action << std::endl;
        return -1;
    }
    return 0;
}



int AgentControlPlane::msg_rsp_process(const msg_t* req_msg, msg_t* res_msg) {
    if (req_msg->action == MSG_ACTION_REQ_QUERY_STATUS) {
        res_msg->magic = req_msg->magic;
        res_msg->action = req_msg->action;
        res_msg->query_id = req_msg->query_id;
        res_msg->msglength = MSG_HEADER_LENGTH + sizeof(msg_status_t);
        msg_status_t stat;
        msg_rsp_process_get_status(&stat);
        memcpy(res_msg->body, &stat, sizeof(msg_status_t));
    }
    return 0;
}


int AgentControlPlane::msg_rsp_process_get_status(msg_status_t* p_stat) {

    memset(p_stat, 0, sizeof(msg_status_t));
    p_stat->ver = MSG_SERVER_VERSION;
    AgentStatus* inst = AgentStatus::get_instance();
    if (!inst) {
        return -1;
    }

    p_stat->start_time = static_cast<uint32_t>(inst->first_packet_time());
    p_stat->last_time = static_cast<uint32_t>(inst->last_packet_time());
    p_stat->total_cap_bytes = static_cast<uint32_t>(inst->total_cap_bytes());
    p_stat->total_cap_packets = static_cast<uint32_t>(inst->total_cap_packets());
    p_stat->total_cap_drop_count = static_cast<uint32_t>(inst->total_cap_drop_count());
    p_stat->total_filter_drop_count = static_cast<uint32_t>(inst->total_filter_drop_count());
    p_stat->total_fwd_drop_count = static_cast<uint32_t>(inst->total_fwd_drop_count());
    return 0;
}




