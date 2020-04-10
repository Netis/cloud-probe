
#include "agent_status.h"

AgentStatus::AgentStatus() {
    _drop_count_at_beginning = 0;

    _first_packet_time = 0;
    _last_packet_time = 0;

    _total_cap_bytes = 0;
    _total_cap_packets = 0;
    _total_cap_drop_count = 0;

    _total_filter_drop_count = 0;
    _total_fwd_drop_count = 0;
}

AgentStatus::~AgentStatus() {

}


int AgentStatus::update_status(uint64_t cur_pkt_time, uint32_t cur_pkt_caplen,
            uint64_t total_fwd_count, uint64_t total_fwd_drop_count, pcap_t* handle){
    if(_first_packet_time == 0) {        
        _first_packet_time = cur_pkt_time;

        struct pcap_stat stat;
        if(handle != NULL && pcap_stats(handle, &stat) == 0) {
            _drop_count_at_beginning = stat.ps_drop + stat.ps_ifdrop;
        }
    }
    _last_packet_time = cur_pkt_time;

    _total_cap_bytes += cur_pkt_caplen;
    _total_cap_packets++;
    struct pcap_stat stat;
    if (handle != NULL && pcap_stats(handle, &stat) == 0) {
        _total_cap_drop_count = stat.ps_drop + stat.ps_ifdrop;
    }

    _total_fwd_drop_count = total_fwd_drop_count;
    _total_filter_drop_count = 0;//_total_cap_packets - total_fwd_count - _total_fwd_drop_count;

    return 0;
}


