#include "socketzmq.h"

#include <iostream>
#include <cstring>
#ifdef WIN32
	#include <WinSock2.h>
	#include <BaseTsd.h>
	#include <windows.h>
	typedef SSIZE_T ssize_t;
	#define usleep Sleep
	#define IPPROTO_GRE 47
#else
#include <arpa/inet.h>
#include <unistd.h>
#endif
#include <pcap/pcap.h>
#include "statislog.h"


PcapExportZMQ::PcapExportZMQ(const std::vector<std::string>& remoteips, int zmq_port, int zmq_hwm, uint32_t keybit,
                             const std::string& bind_device, const int send_buf_size, double mbps) :
        _remoteips(remoteips),
        _zmq_port(zmq_port),
        _zmq_hwm(zmq_hwm),
        _keybit(keybit),
        _bind_device(bind_device),
        _send_buf_size(send_buf_size),
        _pkts_bufs(remoteips.size()) {
    setExportTypeAndMbps(exporttype::zmq, mbps);
    for (size_t i = 0; i < remoteips.size(); ++i) {
        _pkts_bufs[i].buf.resize(MAX_BATCH_BUF_LENGTH, '\0');
        _pkts_bufs[i].batch_bufpos = sizeof(batch_pkts_hdr_t);
        _pkts_bufs[i].batch_hdr = { htons(BatchPktsBuf::BATCH_PKTS_VERSION), 0, htonl(keybit) };
        _pkts_bufs[i].first_pktsec = 0;
   }
}

PcapExportZMQ::~PcapExportZMQ() {
    closeExport();
}

int PcapExportZMQ::initSockets(size_t index, uint32_t keybit) {
    (void)keybit;

    _zmq_contexts.emplace_back(1);
    _zmq_sockets.emplace_back(_zmq_contexts[index], ZMQ_PUSH);
    zmq::socket_t& socket = _zmq_sockets[index];
    std::string connect_addr = "tcp://" + _remoteips[index] + ":" + std::to_string(_zmq_port);

    int32_t linger_ms = 10 * 1000;
    for (size_t i = 0; i < _remoteips.size(); ++i) {
        _zmq_sockets[i].set(zmq::sockopt::linger, linger_ms);
        _zmq_sockets[i].set(zmq::sockopt::sndhwm, _zmq_hwm);
    }

    socket.connect(connect_addr);
    return 0;
}

int PcapExportZMQ::initExport() {
    for (size_t i = 0; i < _remoteips.size(); ++i) {
        int ret = initSockets(i, _keybit);
        if (ret != 0) {
            std::cerr << "Failed with index: " << i << std::endl;
            return ret;
        }
    }
    return 0;
}

int PcapExportZMQ::closeExport() {
    for (size_t i = 0; i < _zmq_sockets.size(); ++i) {
        flushBatchBuf(i);
    }
    _zmq_sockets.clear();
    _zmq_contexts.clear();
    return 0;
}


int PcapExportZMQ::exportPacket(const struct pcap_pkthdr* header, const uint8_t* pkt_data, int direct) {
    int ret = 0;
    uint64_t us;

    if(direct == PKTD_UNKNOWN)
        return -1;

    us = tv2us(&header->ts);
    if(_check_mbps_cb(us, header->caplen) < 0)
        return -1;
    for (size_t i = 0; i < _remoteips.size(); ++i) {
        ret += exportPacket(i, header, pkt_data, direct);
    }
    return ret;
}


int PcapExportZMQ::flushBatchBuf(size_t index) {
    auto& pkts_buf = _pkts_bufs[index];
    auto& socket = _zmq_sockets[index];
    auto& buf = pkts_buf.buf;

    int drop_pkts_num = pkts_buf.batch_hdr.pkts_num;
    pkts_buf.batch_hdr.pkts_num = htons(pkts_buf.batch_hdr.pkts_num);
    std::memcpy(reinterpret_cast<void*>(&(buf[0])), &pkts_buf.batch_hdr, sizeof(pkts_buf.batch_hdr));

    auto ret = socket.send(zmq::buffer(&buf[0], pkts_buf.batch_bufpos), zmq::send_flags::dontwait);
    if (ret.has_value()) {
        drop_pkts_num = 0;
    } else {
        // std::cout<<"send failed."<<std::endl;  // send failed
    }
    return drop_pkts_num;
}

int PcapExportZMQ::exportPacket(size_t index, const struct pcap_pkthdr* header, const uint8_t* pkt_data, int direct) {
    (void)direct;
    auto& pkts_buf = _pkts_bufs[index];
    int drop_pkts_num = 0;

    if (pkts_buf.batch_hdr.pkts_num == 0) {
        pkts_buf.first_pktsec = header->ts.tv_sec;
    }

    uint16_t length = (uint16_t) (header->caplen <= 65535 ? header->caplen : 65535);

    pmr_pkthdr_t small_pkthdr = { htonl((uint32_t)header->ts.tv_sec),
                                  htonl((uint32_t)header->ts.tv_usec),
                                  htonl((uint32_t)header->caplen),
                                  htonl((uint32_t)header->len) };
    auto& buf = pkts_buf.buf;
    if (pkts_buf.batch_hdr.pkts_num >= 65535
        || header->ts.tv_sec > pkts_buf.first_pktsec + MAX_PKTS_TIMEDIFF_S // 3 second timeout
        || pkts_buf.batch_bufpos + sizeof(length) + sizeof(small_pkthdr) + length > MAX_BATCH_BUF_LENGTH) {

        drop_pkts_num = flushBatchBuf(index);

        pkts_buf.first_pktsec = header->ts.tv_sec;
        pkts_buf.batch_bufpos = sizeof(pkts_buf.batch_hdr);
        pkts_buf.batch_hdr.pkts_num = 0;
    }

    uint16_t hlen = htons(length);
    std::memcpy(&(buf[pkts_buf.batch_bufpos]), &hlen, sizeof(hlen));
    std::memcpy(&(buf[pkts_buf.batch_bufpos + sizeof(length)]), &small_pkthdr, sizeof(small_pkthdr));
    std::memcpy(&(buf[pkts_buf.batch_bufpos + sizeof(length) + sizeof(small_pkthdr)]), pkt_data, length);
    pkts_buf.batch_bufpos += sizeof(length) + sizeof(small_pkthdr) + length;
    pkts_buf.batch_hdr.pkts_num++;
    return drop_pkts_num;
}
