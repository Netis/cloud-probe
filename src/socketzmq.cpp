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
#include <fstream>
#include <boost/filesystem.hpp>
#include "pcap/vlan.h"
#include "statislog.h"

static uint32_t makeMplsHdr(int direct, int serviceTag)
{
    uint32_t flag = 0;
    mplsHdr *hdr = (mplsHdr *)&flag;
    hdr->magic_number = 1;
    hdr->rra = direct;

    hdr->service_tag_h = serviceTag >> 4;
    hdr->service_tag_l = serviceTag & 0x0f;

    hdr->bottom = 1;
    hdr->reserved2 = 0xff;
    return flag;
}

static bool uuid_to_bytes(const std::string &uuid, uint8_t uuid_bytes[16])
{
    std::string clean_uuid = uuid;
    clean_uuid.erase(std::remove(clean_uuid.begin(), clean_uuid.end(), '-'), clean_uuid.end());

    if (clean_uuid.length() != 32)
    {
        return false;
    }

    for (size_t i = 0; i < clean_uuid.length(); i += 2)
    {
        std::string byte_string = clean_uuid.substr(i, 2);
        uuid_bytes[i / 2] = static_cast<char>(strtol(byte_string.c_str(), nullptr, 16));
    }
    return true;
}

static void getCPUuid(uint8_t uuid[16])
{
    std::ifstream file("/usr/local/bin/uuid");
    if (!file.is_open())
    {
        std::cerr << "Failed to open file: /usr/local/bin/uuid" << std::endl;
        return;
    }

    std::string uuid_str;
    std::getline(file, uuid_str);
    file.close();

    std::cout << "Get CP uuid: " << uuid_str << std::endl;
    if (uuid_str.size() != 36)
    {
        std::cerr << "Invalid UUID format: " << uuid_str << std::endl;
        return;
    }

    if (!uuid_to_bytes(uuid_str, uuid))
    {
        std::cerr << "Failed to convert UUID to bytes." << std::endl;
        return;
    }

    std::cout << "Set CP uuid in hex format: ";
    for (size_t i = 0; i < 16; ++i)
    {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(uuid[i]);
    }
    std::cout << std::dec << std::endl;

    return;
}

PcapExportZMQ::PcapExportZMQ(const std::vector<std::string> &remoteips, int zmq_port, int zmq_hwm, uint32_t keybit,
                             const std::string &bind_device, const int send_buf_size, double mbps,
                             LogFileContext &ctx) : _remoteips(remoteips),
                                                    _zmq_port(zmq_port),
                                                    _zmq_hwm(zmq_hwm),
                                                    _keybit(keybit),
                                                    _bind_device(bind_device),
                                                    _send_buf_size(send_buf_size),
                                                    _pkts_bufs(remoteips.size()),
                                                    _ctx(ctx)
{
    setExportTypeAndMbps(exporttype::zmq, mbps);
    uint8_t uuid[16];
    memset(uuid, 0, sizeof(uuid));
    getCPUuid(uuid);
    for (size_t i = 0; i < remoteips.size(); ++i)
    {
        _pkts_bufs[i].buf.resize(MAX_BATCH_BUF_LENGTH, '\0');
        _pkts_bufs[i].batch_bufpos = sizeof(batch_pkts_hdr_t);
        _pkts_bufs[i].batch_hdr = {htons(BatchPktsBuf::BATCH_PKTS_VERSION), 0, htonl(keybit)};
        memcpy(_pkts_bufs[i].batch_hdr.uuid, uuid, sizeof(uuid));
        _pkts_bufs[i].first_pktsec = 0;
    }
}

PcapExportZMQ::~PcapExportZMQ()
{
    closeExport();
}

int PcapExportZMQ::initSockets(size_t index, uint32_t keybit)
{
    _zmq_contexts.emplace_back(1);
    _zmq_sockets.emplace_back(_zmq_contexts[index], ZMQ_PUSH);
    zmq::socket_t &socket = _zmq_sockets[index];
    std::string connect_addr = "tcp://" + _remoteips[index] + ":" + std::to_string(_zmq_port);

    uint32_t linger_ms = 10 * 1000;
    for (size_t i = 0; i < _remoteips.size(); ++i)
    {
        _zmq_sockets[i].setsockopt(ZMQ_LINGER, linger_ms);
        _zmq_sockets[i].setsockopt(ZMQ_SNDHWM, _zmq_hwm);
    }

    socket.connect(connect_addr);
    return 0;
}

int PcapExportZMQ::initExport()
{
    for (size_t i = 0; i < _remoteips.size(); ++i)
    {
        int ret = initSockets(i, _keybit);
        if (ret != 0)
        {
            output_buffer = std::string("Failed with index: ") + std::to_string(i);
            _ctx.log(output_buffer, log4cpp::Priority::ERROR);
            std::cerr << output_buffer << std::endl;
            return ret;
        }
    }
    return 0;
}

int PcapExportZMQ::closeExport()
{
    for (size_t i = 0; i < _zmq_sockets.size(); ++i)
    {
        flushBatchBuf(i);
    }
    _zmq_sockets.clear();
    _zmq_contexts.clear();
    return 0;
}

int PcapExportZMQ::exportPacket(const struct pcap_pkthdr *header, const uint8_t *pkt_data, int direct)
{
    uint64_t us;
    if (direct == PKTD_UNKNOWN)
        return -1;
    us = tv2us(&header->ts);
    if (_check_mbps_cb(us, header->caplen) < 0)
        return 0;
    _fwd_byte = 0;
    _fwd_cnt = 0;
    for (size_t i = 0; i < _remoteips.size(); ++i)
    {
        exportPacket(i, header, pkt_data, direct);
    }
    return 0;
}

int PcapExportZMQ::flushBatchBuf(size_t index)
{
    auto &pkts_buf = _pkts_bufs[index];
    auto &socket = _zmq_sockets[index];
    auto &buf = pkts_buf.buf;
    uint64_t send_num = pkts_buf.batch_hdr.pkts_num;
    pkts_buf.batch_hdr.pkts_num = htons(pkts_buf.batch_hdr.pkts_num);
    std::memcpy(reinterpret_cast<void *>(&(buf[0])), &pkts_buf.batch_hdr, sizeof(pkts_buf.batch_hdr));

    auto ret = socket.send(zmq::buffer(&buf[0], pkts_buf.batch_bufpos), zmq::send_flags::dontwait);
    if (ret.has_value())
    {
        _fwd_cnt += send_num;
        _fwd_byte += pkts_buf.batch_bufpos;
    }
    else
    {
        // std::cout<<"send failed."<<std::endl;  // send failed
    }
    return 0;
}

int PcapExportZMQ::exportPacket(size_t index, const struct pcap_pkthdr *header, const uint8_t *pkt_data, int direct)
{
    (void)direct;

    auto &pkts_buf = _pkts_bufs[index];

    if (pkts_buf.batch_hdr.pkts_num == 0)
    {
        pkts_buf.first_pktsec = header->ts.tv_sec;
    }

    uint16_t length = (uint16_t)(header->caplen <= 65531 ? header->caplen : 65531) + sizeof(mplsHdr);

    pmr_pkthdr_t small_pkthdr = {htonl((uint32_t)header->ts.tv_sec),
                                 htonl((uint32_t)header->ts.tv_usec),
                                 htonl((uint32_t)header->caplen + sizeof(mplsHdr)),
                                 htonl((uint32_t)header->len + sizeof(mplsHdr))};
    auto &buf = pkts_buf.buf;
    if (pkts_buf.batch_hdr.pkts_num >= 65535 || (pkts_buf.first_pktsec != 0 && header->ts.tv_sec > pkts_buf.first_pktsec + MAX_PKTS_TIMEDIFF_S) // 3 second timeout
        || pkts_buf.batch_bufpos + sizeof(length) + sizeof(small_pkthdr) + length > MAX_BATCH_BUF_LENGTH)
    {
        std::string output_buffer = std::string("Send zmq message, last packet time: ") + std::to_string(header->ts.tv_sec)
                        + ", first packet time: " +  std::to_string(pkts_buf.first_pktsec) + ".";
            _ctx.log(output_buffer, log4cpp::Priority::INFO);

        flushBatchBuf(index);

        pkts_buf.first_pktsec = header->ts.tv_sec;
        pkts_buf.batch_bufpos = sizeof(pkts_buf.batch_hdr);
        pkts_buf.batch_hdr.pkts_num = 0;
    }

    if (pkts_buf.first_pktsec == 0)
    {
        pkts_buf.first_pktsec = header->ts.tv_sec;
    }

    uint16_t hlen = htons(length);
    uint32_t buff_pos = pkts_buf.batch_bufpos;
    std::memcpy(&(buf[buff_pos]), &hlen, sizeof(hlen));
    buff_pos += sizeof(length);

    std::memcpy(&(buf[buff_pos]), &small_pkthdr, sizeof(small_pkthdr));
    buff_pos += sizeof(small_pkthdr);

    ether_header *hdr = (ether_header *)pkt_data;

    vlan_tag *vlan_hdr = nullptr;

    if (ntohs(hdr->ether_type) == ETHERTYPE_VLAN)
    {
        vlan_hdr = (vlan_tag *)(pkt_data + sizeof(ether_header));
        vlan_hdr->vlan_tci = htons(ETHER_TYPE_MPLS);
    }
    else
    {
        hdr->ether_type = htons(ETHER_TYPE_MPLS);
    }

    std::memcpy(&(buf[buff_pos]), pkt_data, sizeof(ether_header));
    buff_pos += sizeof(ether_header);

    if (vlan_hdr != nullptr)
    {
        std::memcpy(&(buf[buff_pos]), vlan_hdr, sizeof(vlan_tag));
        buff_pos += sizeof(vlan_tag);
    }

    mplsHdr mplshdr;
    uint32_t mplsTag = makeMplsHdr(direct, _keybit);
    memcpy(&mplshdr, &mplsTag, sizeof(mplshdr));

    std::memcpy(&(buf[buff_pos]), &mplshdr, sizeof(mplsHdr));
    buff_pos += sizeof(mplsHdr);
    if (vlan_hdr != nullptr)
    {
        std::memcpy(&(buf[buff_pos]),
                    pkt_data + sizeof(ether_header) + sizeof(vlan_tag), length - sizeof(ether_header) - sizeof(mplsHdr) - sizeof(vlan_tag));
    }
    else
    {
        std::memcpy(&(buf[buff_pos]),
                    pkt_data + sizeof(ether_header), length - sizeof(ether_header) - sizeof(mplsHdr));
    }

    pkts_buf.batch_bufpos += sizeof(length) + sizeof(small_pkthdr) + length;
    pkts_buf.batch_hdr.pkts_num++;
    return 0;
}

void PcapExportZMQ::checkSendBuf()
{
    _fwd_byte = 0;
    _fwd_cnt = 0;
    auto tt = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());

    for (unsigned int i = 0; i < _pkts_bufs.size(); i++)
    {
        if (_pkts_bufs[i].first_pktsec != 0 && _pkts_bufs[i].batch_hdr.pkts_num != 0 && tt > _pkts_bufs[i].first_pktsec + MAX_PKTS_TIMEDIFF_S)
        {
            std::string output_buffer = std::string("Send zmq message, current time: ") + std::to_string(tt)
                        + ", first packet time: " +  std::to_string(_pkts_bufs[i].first_pktsec) + ".";
            _ctx.log(output_buffer, log4cpp::Priority::INFO);

            flushBatchBuf(i);

            _pkts_bufs[i].first_pktsec = 0;
            _pkts_bufs[i].batch_bufpos = sizeof(_pkts_bufs[i].batch_hdr);
            _pkts_bufs[i].batch_hdr.pkts_num = 0;
        }
    }
    return;
}
