#ifndef SRC_CONTROL_ITF_H_
#define SRC_CONTROL_ITF_H_


#define MAX_MSG_CONTENT_LENGTH  (256)
#define MSG_MAGIC_NUMBER   (0x504D3230)
#define MSG_HEADER_LENGTH  (16)

/* message struction, reference doc/msg.md */
typedef struct msg {
    /* header */
    uint32_t magic;
    uint32_t msglength;
    uint32_t action;
    uint32_t query_id;

    /* body */
    char body[MAX_MSG_CONTENT_LENGTH];
}  __attribute__((packed)) msg_t, * msg_ptr_t;

typedef enum msg_action_req_type {
    MSG_ACTION_REQ_INVALID = 0x0000,
    MSG_ACTION_REQ_QUERY_STATUS = 0x0001,
    MSG_ACTION_REQ_MAX
} msg_act_req_type_e;


typedef struct msg_status {
    uint32_t ver;
    uint32_t start_time;
    uint32_t last_time;
    uint32_t total_cap_bytes;
    uint32_t total_cap_packets;
    uint32_t total_cap_drop_count;
    uint32_t total_filter_drop_count;
    uint32_t total_fwd_drop_count;
}__attribute__((packed)) msg_status_t, * msg_status_ptr_t;





#endif


