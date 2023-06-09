
#include "agent_status.h"

AgentStatus::AgentStatus() {
    _drop_count_at_beginning = 0;

    _first_packet_time = 0;
    _last_packet_time = 0;

    _total_cap_bytes = 0;
    _total_cap_packets = 0;
    _total_cap_drop_count = 0;

    _total_fwd_count = 0;
    _total_fwd_bytes = 0;
}

AgentStatus::~AgentStatus() {

}

int AgentStatus::reset_agent_status() {
    _drop_count_at_beginning = 0;

    _first_packet_time = 0;
    _last_packet_time = 0;

    _total_cap_bytes = 0;
    _total_cap_packets = 0;
    _total_cap_drop_count = 0;

    _total_fwd_count = 0;
    _total_fwd_bytes = 0;
    return 0;
}


int AgentStatus::update_capture_status(uint64_t cur_pkt_time, uint64_t total_pkt_caplen,  uint64_t fwd_pkt_caplen,
            uint64_t total_fwd_count, uint64_t total_cap_count, pcap_t* handle){
    if(_first_packet_time == 0) {        
        _first_packet_time = cur_pkt_time;

        struct pcap_stat stat;
        if(handle != NULL && pcap_stats(handle, &stat) == 0) {
            _drop_count_at_beginning = stat.ps_drop;
        }
    }
    _last_packet_time = cur_pkt_time;

    _total_cap_bytes = total_pkt_caplen;
    _total_fwd_bytes =fwd_pkt_caplen;

    struct pcap_stat stat;
    if (handle != NULL && pcap_stats(handle, &stat) == 0) {
        
        _total_cap_drop_count = stat.ps_drop;
        _total_cap_drop_count -= _drop_count_at_beginning;
    }
    _total_cap_packets = total_cap_count;
    _total_fwd_count = total_fwd_count;

    return 0;
}


