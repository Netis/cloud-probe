#include "statislog.h"
#include <cstring>
#include <iostream>

std::string StatisLogContext::getTimeString() {
    char time_buffer[LOG_TIME_BUF_LEN];
    const auto now = time(NULL);
    const auto* ts = localtime(&now);
    strftime(time_buffer, LOG_TIME_BUF_LEN, "%Y-%m-%d %H:%M:%S", ts);
    return std::string("[") + time_buffer + std::string("] ");
}

StatisLogContext::StatisLogContext(bool bQuiet) :
    bQuiet_(bQuiet) {
    log_count_      = 0;
    start_log_time_ = 0;
    last_log_time_  = 0;
    first_pkt_time_ = 0;
    start_drop_     = 0;
    total_cap_bytes_= 0;
    total_packets_  = 0;
    std::memset(title_buffer_, 0, sizeof(title_buffer_));
    std::memset(time_buffer_, 0, sizeof(time_buffer_));
    std::memset(message_buffer_, 0, sizeof(message_buffer_));
    std::memset(statis_buffer_, 0, sizeof(statis_buffer_));
    std::memset(bps_pps_buffer_, 0, sizeof(bps_pps_buffer_));
}

//void StatisLogContext::setQuiet(bool bQuiet) {
//    bQuiet_ = bQuiet;
//}
//
//bool StatisLogContext::getQuiet() const {
//    return bQuiet_;
//}

void StatisLogContext::initStatisLogFmt(const char* name, const char* title) {
    std::time_t now = std::time(NULL);
    __process_time_buffer(now);
    start_log_time_ = now;
    std::cout << "[" << name << "] " << time_buffer_ << " starts." << std::endl;
    std::strncpy(title_buffer_, title, sizeof(title_buffer_)-1);
}

void StatisLogContext::__process_first_packet(uint64_t pkt_time, pcap_t *handle) {
    pcap_stat stat;
    first_pkt_time_ = pkt_time;
    if(handle!=NULL && pcap_stats(handle, &stat) == 0) {
        start_drop_ = stat.ps_drop;
    }
}

void StatisLogContext::__process_title() {
    if( log_count_ <= 0 ) {
        std::cout << title_buffer_ << std::endl;
        log_count_ = LOG_PROMPT_COUNT;
    }
    log_count_--;
}

void StatisLogContext::__process_time_buffer(std::time_t now) {
    std::tm* ts = std::localtime(&now);
    std::strftime(time_buffer_, LOG_TIME_BUF_LEN, "%Y-%m-%d %H:%M:%S", ts);
}

void StatisLogContext::__process_bps_pps_buffer(std::time_t timep) {
    std::time_t delta_time = timep - last_log_time_;
    // live_time, bps, pps
    if(last_log_time_ == 0 || delta_time == 0) {
        std::snprintf(bps_pps_buffer_, sizeof(bps_pps_buffer_) - 1, "%ld,0,0", timep-start_log_time_);
    } else {
        std::snprintf(bps_pps_buffer_, sizeof(bps_pps_buffer_) - 1, "%ld,%ld,%ld", timep-start_log_time_,
                     total_cap_bytes_*8 / delta_time, total_packets_ / delta_time);
    }
}

void StatisLogContext::__process_send_statis_buffer(uint64_t pkt_time, uint64_t filter_drop, pcap_t *handle) {
    // first_packet_time, pkt_time,
    // ps_recv, ps_drop - start_drop, ps_ifdrop, filter_drop
    struct pcap_stat stat;
    if (handle != NULL && pcap_stats(handle, &stat) == 0) {
        std::snprintf(statis_buffer_, sizeof(statis_buffer_), "%ld,%ld,%u,%u,%u,%ld", first_pkt_time_, pkt_time, stat.ps_recv,
                     stat.ps_drop - start_drop_, stat.ps_ifdrop, filter_drop);
    } else {
        std::snprintf(statis_buffer_, sizeof(statis_buffer_), "%ld,%ld,0,0,0,%ld", first_pkt_time_, pkt_time, filter_drop);
    }
}

//void StatisLogContext::__process_recv_statis_buffer(uint64_t pkt_time) {
//    // first_packet_time, pkt_time, ps_recv
//    std::sprintf(statis_buffer_, "%ld,%ld,%ld", first_pkt_time_, pkt_time, total_packets_);
//}

void StatisLogContext::__inline_update_statis(std::time_t timep) {
    last_log_time_ = timep;
    total_cap_bytes_ = 0;
    total_packets_ = 0;
}

GreStatisLogContext::GreStatisLogContext(bool bQuiet) :
    StatisLogContext(bQuiet) {
    last_drop_count_    = 0;
    std::memset(gre_buffer_, 0, sizeof(gre_buffer_));
}

GreSendStatisLog::GreSendStatisLog(bool bQuiet) :
    GreStatisLogContext(bQuiet) {
}

void GreSendStatisLog::initSendLog(const char* name) {
    init(name);
}

void GreSendStatisLog::logSendStatis(uint64_t pkt_time, uint32_t caplen, uint64_t count, uint64_t drop_count,
                   uint64_t filter_drop, pcap_t *handle) {
    logSendStatisGre(pkt_time, caplen, count, drop_count, filter_drop, handle);
}

void GreSendStatisLog::init(const char* name) {
    initStatisLogFmt(name, "# [now] first_time,pkt_time,ps_recv,ps_drop,ps_ifdrop,filter_drop,,"
        "live_time,bps,pps,,send_num,send_drop");
}

void GreSendStatisLog::logSendStatisGre(uint64_t pkt_time, uint32_t caplen, uint64_t count, uint64_t drop_count,
                                        uint64_t filter_drop, pcap_t *handle) {
    if (bQuiet_) {
        return;
    }

    if(first_pkt_time_ == 0) {
        __process_first_packet(pkt_time, handle);
    }

    // print statistical info
    std::time_t now = std::time(NULL);
    if (last_log_time_ != now) {
        __process_title();
        logSendStatisGre(now, pkt_time, count, drop_count, filter_drop, handle);
        last_drop_count_ = drop_count;
    }
    total_cap_bytes_ += caplen;
    total_packets_++;
}

void GreSendStatisLog::logSendStatisGre(std::time_t current, uint64_t pkt_time, uint64_t count,
                      uint64_t drop_count, uint64_t filter_drop, pcap_t *handle) {
    // [now]: statis,bps_pps
    __process_time_buffer(current);
    __process_send_statis_buffer(pkt_time, filter_drop, handle);
    __process_bps_pps_buffer(current);
    __process_send_gre_buffer(count, drop_count);
    __inline_update_statis(current);

    std::snprintf(message_buffer_, sizeof(message_buffer_), "[%s] %s,,%s,,%s", time_buffer_,
                  statis_buffer_, bps_pps_buffer_, gre_buffer_);
    std::cout << message_buffer_ << std::endl;
}

void GreSendStatisLog::__process_send_gre_buffer(uint64_t num, uint64_t drop_count) {
    // send_num,send_pos,occupy
    std::snprintf(gre_buffer_, sizeof(gre_buffer_), "%ld,%ld:%ld.", num, drop_count,
                  drop_count - last_drop_count_);
}