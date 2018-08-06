#ifndef SRC_STATISLOG_H_
#define SRC_STATISLOG_H_

#include <ctime>
#include <stdint.h>
#include <pcap/pcap.h>

#include <string>

#define LOG_PROMPT_COUNT 20
#define LOG_TIME_BUF_LEN 20
#define LOG_BUFFER_LEN 256
#define LOG_TICK_COUNT 100

class StatisLogContext {
protected:
    bool bQuiet_;
    int log_count_;
    std::time_t start_log_time_;
    std::time_t last_log_time_;
    uint64_t first_pkt_time_;
    uint32_t start_drop_;
    uint64_t total_cap_bytes_;
    uint64_t total_packets_;
    char time_buffer_[LOG_TIME_BUF_LEN];
    char title_buffer_[LOG_BUFFER_LEN];
    char message_buffer_[LOG_BUFFER_LEN];
    char statis_buffer_[LOG_BUFFER_LEN];
    char bps_pps_buffer_[LOG_BUFFER_LEN];

public:
    static std::string getTimeString();

    explicit StatisLogContext(bool bQuiet = false);
//    void setQuiet(bool bQuiet);
//    bool getQuiet() const;
protected:
    void initStatisLogFmt(const char* name, const char* title);

    void __process_first_packet(uint64_t pkt_time, pcap_t* handle = NULL);

    void __process_title();

    void __process_time_buffer(std::time_t now);

    void __process_bps_pps_buffer(std::time_t timep);

    void __process_send_statis_buffer(uint64_t pkt_time, uint64_t filter_drop = 0, pcap_t* handle = NULL);

//    void __process_recv_statis_buffer(uint64_t pkt_time);
    void __inline_update_statis(std::time_t timep);
};

class GreStatisLogContext : public StatisLogContext {
protected:
    uint64_t last_drop_count_;
    char gre_buffer_[LOG_BUFFER_LEN];
public:
    explicit GreStatisLogContext(bool bQuiet = false);
};

class StatisSendLog {
public:
    virtual void initSendLog(const char* name) = 0;

    virtual void logSendStatis(uint64_t pkt_time, uint32_t caplen, uint64_t count, uint64_t drop_count,
                               uint64_t filter_drop, pcap_t* handle) = 0;
};

class GreSendStatisLog : public StatisSendLog, GreStatisLogContext {
public:
    explicit GreSendStatisLog(bool bQuiet = false);

    void initSendLog(const char* name);

    void logSendStatis(uint64_t pkt_time, uint32_t caplen, uint64_t count = 0, uint64_t drop_count = 0,
                       uint64_t filter_drop = 0, pcap_t* handle = NULL);

    void init(const char* name);

    void logSendStatisGre(uint64_t pkt_time, uint32_t caplen, uint64_t count, uint64_t drop_count,
                          uint64_t filter_drop = 0, pcap_t* handle = NULL);

    void logSendStatisGre(std::time_t current, uint64_t pkt_time, uint64_t count,
                          uint64_t drop_count, uint64_t filter_drop = 0, pcap_t* handle = NULL);

protected:
    void __process_send_gre_buffer(uint64_t num, uint64_t drop_count);
};

#endif // SRC_STATISLOG_H_
