#ifndef SRC_SOCKETZMQ_H_
#define SRC_SOCKETZMQ_H_

#ifndef WIN32
	#include <netinet/in.h>
#endif
#include <string>
#include <vector>
#include "zmq.hpp"
#include "pcapexport.h"



typedef struct PmrPktHdr {
	uint32_t tv_sec;   // epoc seconds.  caution: unix 2038 problem
	uint32_t tv_usec;  // and microseconds
	uint32_t caplen;   // actual capture length
	uint32_t len;      // wire packet length
} pmr_pkthdr_t, * pmr_pkthdr_ptr_t;

typedef struct batch_pkts_header {
	uint16_t version;
	uint16_t pkts_num;
	uint32_t keybit;
} batch_pkts_hdr_t;

struct BatchPktsBuf {
    batch_pkts_hdr_t batch_hdr;
    // buf format as below:
	// | batch_hdr | (pkt_data length  + pkt_hdr  + pkt_data) | (pkt_data_length  + pkt_hdr  + pkt_data) | ...
	// | 8 bytes   | (2 bytes          + 16 bytes + n bytes ) | (2 bytes          + 16 bytes + n bytes ) | ...
    std::vector<char> buf;
    uint32_t batch_bufpos;
    __time_t first_pktsec;
public:
	static constexpr uint16_t BATCH_PKTS_VERSION = 1;
};

class PcapExportZMQ : public PcapExportBase {
protected:
    std::vector<std::string> _remoteips;
	int _zmq_port;
	int _zmq_hwm;
    uint32_t _keybit;
    std::string _bind_device;
    int _send_buf_size;
	std::vector<zmq::context_t> _zmq_contexts;
    std::vector<zmq::socket_t> _zmq_sockets;
    std::vector<BatchPktsBuf> _pkts_bufs;
    constexpr static uint32_t MAX_PKTS_TIMEDIFF_S = 1;
	constexpr static uint32_t MAX_BATCH_BUF_LENGTH = 1 * 1024 * 1024;

private:
    int initSockets(size_t index, uint32_t keybit);
    int exportPacket(size_t index, const struct pcap_pkthdr *header, const uint8_t *pkt_data, int direct);
    int flushBatchBuf(size_t index);

public:
    PcapExportZMQ(const std::vector<std::string>& remoteips, int zmq_port, int zmq_hwm, uint32_t keybit,
				  const std::string& bind_device, const int send_buf_size);
    ~PcapExportZMQ();
    int initExport();
    int exportPacket(const struct pcap_pkthdr *header, const uint8_t *pkt_data, int direct);
    int closeExport();
};

#endif // SRC_SOCKETZMQ_H_