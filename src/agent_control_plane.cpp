
#include <iostream>
#include <cstring>
#include <chrono>
#include <boost/format.hpp>
#include "agent_status.h"
#include "agent_control_plane.h"
#include <fstream>


AgentControlPlane::AgentControlPlane(LogFileContext& ctx, uint16_t port):
        _zmq_context(DEFAULT_ZMQ_IO_THREAD),
        _zmq_socket(_zmq_context, ZMQ_REP),
        _break_loop(0),
        _ctx(ctx){
    _zmq_url = boost::str(boost::format("tcp://127.0.0.1:%1%") % port);
    init();
}

AgentControlPlane::~AgentControlPlane()
{
    _break_loop = 1;
    _thread.join();
}
int AgentControlPlane::msg_req_check(const msg_t* req_msg){
    /* check length */
    if(req_msg->msglength != sizeof(msg_t))
    {
        output_buffer = std::string("[pktminerg] msg_req_check failed: invalid msg length ") + std::to_string(req_msg->msglength);
        _ctx.log(output_buffer, log4cpp::Priority::ERROR);
        std::cerr << output_buffer << std::endl;
        return -1;
    }
    /* check magic */
    if (req_msg->magic != MSG_MAGIC_NUMBER) {
        output_buffer = std::string("[pktminerg] msg_req_check failed: invalid msg magic number ") + std::to_string(req_msg->magic);
        _ctx.log(output_buffer, log4cpp::Priority::ERROR);
        std::cerr << output_buffer << std::endl;
        return -1;
    }
    /* check action */
    if (req_msg->action >= MSG_ACTION_REQ_MAX) {
        output_buffer = std::string("[pktminerg] msg_req_check failed: invalid action request:") + std::to_string(req_msg->action);
        _ctx.log(output_buffer, log4cpp::Priority::ERROR);
        std::cerr << output_buffer << std::endl;
        return -1;
    }
    return 0;
}



int AgentControlPlane::msg_rsp_process(const msg_t* req, msg_t* rep) {
    if (req->action == MSG_ACTION_REQ_QUERY_STATUS) {
        rep->magic = req->magic;
        rep->action = req->action;
        rep->query_id = req->query_id;
        rep->msglength = sizeof(msg_t) + sizeof(msg_status_t);
        msg_status_t stat;
        msg_rsp_process_get_status(&stat);
        memcpy((char*)rep + sizeof(msg_t), &stat, sizeof(msg_status_t));
    }
    return 0;
}


int AgentControlPlane::msg_rsp_process_get_status(msg_status_t* p_stat) {
    //std::ofstream f;
    
    memset(p_stat, 0, sizeof(msg_status_t));
    p_stat->ver = MSG_SERVER_VERSION;
    AgentStatus* inst = AgentStatus::get_instance();
    if (!inst) {
        return -1;
    }
    p_stat->start_time = static_cast<uint32_t>(inst->first_packet_time());
    p_stat->last_time = static_cast<uint32_t>(inst->last_packet_time());
    p_stat->total_cap_bytes = inst->total_cap_bytes();
    p_stat->total_cap_packets = inst->total_cap_packets();
    p_stat->total_cap_drop_count = inst->total_cap_drop_count();
    p_stat->total_fwd_bytes = inst->total_fwd_bytes();
    p_stat->total_fwd_count = inst->total_fwd_count();
    return 0;
}

void AgentControlPlane::step() {
    msg_t req,* rep;
    char tmp[sizeof(msg_t) + sizeof(msg_status_t)];

    rep = (msg_t*)tmp;

    zmq::message_t msg_recv;
    zmq::recv_result_t recv_ret = {};
    recv_ret = _zmq_socket.recv(msg_recv, zmq::recv_flags::dontwait);
    if (!recv_ret) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
        return;
    }

    if (msg_recv.size() != sizeof(msg_t))
    {
        output_buffer = std::string("[pktminerg] zmq recv req msg length ") + std::to_string(msg_recv.size()) + " not match";
        _ctx.log(output_buffer, log4cpp::Priority::ERROR);
        std::cerr << output_buffer << std::endl;
        return;
    }

    memcpy(&req, msg_recv.data(),sizeof(msg_t));

    if(msg_req_check(&req) < 0)
        return;
    msg_rsp_process(&req, rep);
    // Send Response
    zmq::message_t msg_send(tmp, sizeof(msg_t) + sizeof(msg_status_t), NULL);
   
    _zmq_socket.send(msg_send, zmq::send_flags::none);

    std::this_thread::sleep_for(std::chrono::milliseconds(1));
}

void AgentControlPlane::init() {
    _zmq_socket.bind(_zmq_url);

    _thread = std::thread([&](){
        while(!_break_loop)
            step();
    });
}



