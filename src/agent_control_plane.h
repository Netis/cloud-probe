#ifndef SRC_MSGSERVER_H_
#define SRC_MSGSERVER_H_


#include <atomic>

#include <pthread.h>
#include <zmq.hpp>

#include "agent_control_itf.h"

class AgentControlPlane {

public:
    AgentControlPlane();
    AgentControlPlane(int zmq_port);
    ~AgentControlPlane();

    int init_msg_server();
    int close_msg_server();


public:
    const static int DEFAULT_ZMQ_IO_THREAD = 16;
    const static int DEFAULT_ZMQ_SERVER_PORT = 5556;

    const static uint32_t MSG_SERVER_VERSION = 0x01;

private:
    int msg_req_process(const char* buf, size_t size, msg_t* req_msg);
    int msg_rsp_process(const msg_t* req_msg, msg_t* res_msg);
    int msg_rsp_process_get_status(msg_status_t* stat);

private:
    static void* run(void*);
    static void on_destroy(void*);

private:
    // zmq
    int _zmq_port;
    zmq::context_t _zmq_context;
    zmq::socket_t _zmq_socket;    

    // pthread
    pthread_attr_t _attr;
    pthread_t _tid;
    // std::thread _msg_server_loop;
};



#endif


