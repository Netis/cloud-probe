#ifndef SRC_AGENT_STATUS_H_
#define SRC_AGENT_STATUS_H_


#include <atomic>

#include <pcap/pcap.h>



class AgentStatus {
public:
    AgentStatus();
    ~AgentStatus();

public:
    static AgentStatus* get_instance() {
        static AgentStatus inst;
        return &inst;
    }

public:
    int update_capture_status(uint64_t cur_pkt_time, uint32_t cur_pkt_caplen,
            uint64_t total_fwd_count, uint64_t total_fwd_drop_count, pcap_t* handle = NULL);
    int reset_agent_status();


public:
    uint64_t first_packet_time() { return _first_packet_time; }
    uint64_t last_packet_time() { return _last_packet_time; }
    uint64_t total_cap_bytes() { return _total_cap_bytes; }
    uint64_t total_cap_packets() { return _total_cap_packets; }
    uint64_t total_cap_drop_count() { return _total_cap_drop_count; }
    uint64_t total_filter_drop_count() { return _total_filter_drop_count; }
    uint64_t total_fwd_drop_count() { return _total_fwd_drop_count; }


private:

    // packet agent metrics
    uint64_t _drop_count_at_beginning;

    std::atomic<uint64_t> _first_packet_time;
    std::atomic<uint64_t> _last_packet_time;
    std::atomic<uint64_t> _total_cap_bytes;
    std::atomic<uint64_t> _total_cap_packets;
    std::atomic<uint64_t> _total_cap_drop_count;
    std::atomic<uint64_t> _total_filter_drop_count;
    std::atomic<uint64_t> _total_fwd_drop_count;
};

#endif


