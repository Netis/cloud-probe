#ifndef SRC_CONTROL_ITF_H_
#define SRC_CONTROL_ITF_H_


#define MSG_MAGIC_NUMBER   (0x504D3230)

// request and response data format, between zmq client and server

/* message struction, reference doc/msg.md */
typedef struct msg {
    /* header */
    uint32_t magic;   // must be 0x50 0x4D 0x32 0x30 in order.
    uint32_t msglength;   // msg length, include header, in bytes.
    uint32_t action;   // list below
    uint32_t query_id;  // the query id to identify each client for req flush
}msg_t;


// support action now
typedef enum msg_action_req_type {
    MSG_ACTION_REQ_INVALID = 0x0000,
    MSG_ACTION_REQ_QUERY_STATUS = 0x0001,
    MSG_ACTION_REQ_MAX
} msg_act_req_type_e;

// action MSG_ACTION_REQ_QUERY_STATUS's response data body.
typedef struct msg_status {
    uint32_t ver;
    uint32_t start_time;
    uint32_t last_time;
    uint64_t total_cap_bytes;
    uint64_t total_cap_packets;
    uint64_t total_cap_drop_count;
    uint64_t total_fwd_bytes;
    uint64_t total_fwd_count;
}msg_status_t;





#endif


