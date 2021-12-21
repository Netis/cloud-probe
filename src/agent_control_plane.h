#ifndef SRC_MSGSERVER_H_
#define SRC_MSGSERVER_H_


#include <atomic>
#include <string>
#include <thread>
#include "zmq.hpp"
#include "agent_control_itf.h"

class AgentControlPlane {

public:
    AgentControlPlane(uint16_t port = 5566);
    ~AgentControlPlane();
public:
    const static int DEFAULT_ZMQ_IO_THREAD = 1;
    const static uint32_t MSG_SERVER_VERSION = 0x01;

private:
    void init();
    void step();
    int msg_req_check(const msg_t* req_msg);
    int msg_rsp_process(const msg_t* req_msg, msg_t* res_msg);
    int msg_rsp_process_get_status(msg_status_t* stat);
private:
    // zmq
    std::string _zmq_url;
    zmq::context_t _zmq_context;
    zmq::socket_t _zmq_socket;
    std::thread _thread;
    int _break_loop;
};



#endif


