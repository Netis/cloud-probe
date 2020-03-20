#include "pcaphandler.h"
#include <iostream>
#include <algorithm>
#include <boost/filesystem.hpp>
#include "scopeguard.h"

PcapHandler::PcapHandler() {
    _gre_count = 0;
    _gre_drop_count = 0;
    _pcap_handle = NULL;
    _pcap_dumpter = NULL;
    std::memset(_errbuf, 0, sizeof(_errbuf));
}

PcapHandler::~PcapHandler() {
    closePcapDumper();
    closePcap();
}

int PcapHandler::openPcapDumper(pcap_t* pcap_handle) {
    closePcapDumper();
    std::string filepath = "pktminer_dump.pcap";
    if (boost::filesystem::exists(filepath)) {
        boost::filesystem::remove(filepath);
    }
    _pcap_dumpter = pcap_dump_open(pcap_handle, filepath.c_str());
    if (_pcap_dumpter == NULL) {
        std::cerr << StatisLogContext::getTimeString() << "Call pcap_dump_open failed, error is "
                  << pcap_geterr(pcap_handle) << "." << std::endl;
        return -1;
    }
    return 0;
}

void PcapHandler::closePcapDumper() {
    if (_pcap_dumpter != NULL) {
        pcap_dump_close(_pcap_dumpter);
        _pcap_dumpter = NULL;
    }
}

void PcapHandler::closePcap() {
    if (_pcap_handle != NULL) {
        pcap_close(_pcap_handle);
        _pcap_handle = NULL;
    }
}

void PcapHandler::packetHandler(const struct pcap_pkthdr* header, const uint8_t* pkt_data) {
    std::for_each(_exports.begin(), _exports.end(),
                  [header, pkt_data, this](std::shared_ptr<PcapExportBase> pcapExport) {
//        if (header->caplen > 1472) {
//            std::cout << "pkt " << _gre_count << ", len: " << header->len << ", caplen: " << header->caplen << std::endl;
//        }
                      int ret = pcapExport->exportPacket(header, pkt_data);
                      if (pcapExport->getExportType() == exporttype::gre) {
                          if (ret == 0) {
                              this->_gre_count++;
                          } else {
                              this->_gre_drop_count++;
                          }
                      } else if (pcapExport->getExportType() == exporttype::zmq) {
                          if (ret == 0) {
                              this->_gre_count++; //TODO: support zmq batch packets
                          } else {
                              this->_gre_drop_count += ret;
                          }
                      }
                  });
    if (_pcap_dumpter) {
        pcap_dump(reinterpret_cast<u_char*>(_pcap_dumpter), header, pkt_data);
    }
    if (_statislog == nullptr) {
        _statislog = std::make_shared<GreSendStatisLog>(false);
        _statislog->initSendLog("pktminerg");
    }
    _statislog->logSendStatis((uint64_t) (header->ts.tv_sec), header->caplen, _gre_count, _gre_drop_count, 0,
                              _pcap_handle);
}

void PcapHandler::addExport(std::shared_ptr<PcapExportBase> pcapExport) {
    _exports.push_back(pcapExport);
}

int PcapHandler::startPcapLoop(int count) {
    if (_pcap_handle == NULL) {
        std::cerr << StatisLogContext::getTimeString() << "The pcap has not created." << std::endl;
        return -1;
    }
    int ret = pcap_loop(_pcap_handle, count, [](uint8_t* user, const struct pcap_pkthdr* h, const uint8_t* data) {
        PcapHandler* p = static_cast<PcapHandler*>(static_cast<void*>(user));
        p->packetHandler(h, data);
    }, reinterpret_cast<uint8_t*>(this));
    if (_statislog == nullptr) {
        _statislog = std::make_shared<GreSendStatisLog>(false);
        _statislog->initSendLog("pktminerg");
    }
    _statislog->logSendStatisGre(std::time(NULL), (uint64_t) std::time(NULL), _gre_count, _gre_drop_count, 0,
                                 _pcap_handle);
    return ret;
}

void PcapHandler::stopPcapLoop() {
    if (_pcap_handle == NULL) {
        std::cerr << StatisLogContext::getTimeString() << "The pcap has not created." << std::endl;
        return;
    }
    pcap_breakloop(_pcap_handle);
}

int PcapOfflineHandler::openPcap(const std::string& dev, const pcap_init_t& param, const std::string& expression,
                                 bool dumpfile) {
    pcap_t* pcap_handle = pcap_open_offline(dev.c_str(), _errbuf);
    if (!pcap_handle) {
        std::cerr << StatisLogContext::getTimeString() << "Call pcap_open_offline failed, error is " << _errbuf << "."
                  << std::endl;
        return -1;
    }
    auto pcapGuard = MakeGuard([pcap_handle]() {
        pcap_close(pcap_handle);
    });

    if (dumpfile) {
        if (openPcapDumper(pcap_handle) != 0) {
            std::cerr << StatisLogContext::getTimeString() << "Call openPcapDumper failed." << std::endl;
            return -1;
        }
    }
    pcapGuard.Dismiss();
    _pcap_handle = pcap_handle;
    return 0;
}

int PcapLiveHandler::openPcap(const std::string& dev, const pcap_init_t& param, const std::string& expression,
                              bool dumpfile) {
    int ret;
    struct bpf_program filter;
    bpf_u_int32 mask = 0;
    bpf_u_int32 net = 0;

    pcap_t* pcap_handle = pcap_create(dev.c_str(), _errbuf);
    if (!pcap_handle) {
        std::cerr << StatisLogContext::getTimeString() << "Call pcap_create failed, error is " << _errbuf << "."
                  << std::endl;
        return -1;
    }
    auto pcapGuard = MakeGuard([pcap_handle]() {
        pcap_close(pcap_handle);
    });

    pcap_set_snaplen(pcap_handle, param.snaplen);
    pcap_set_timeout(pcap_handle, param.timeout);
    pcap_set_promisc(pcap_handle, param.promisc);
    ret = pcap_set_buffer_size(pcap_handle, param.buffer_size);
    if (ret != 0) {
        std::cerr << StatisLogContext::getTimeString() << "Call pcap_set_buffer_size to " << param.buffer_size
                  << " failed." << std::endl;
        return -1;
    }
    ret = pcap_activate(pcap_handle);
    if (ret != 0) {
        std::cerr << StatisLogContext::getTimeString() << "Call pcap_activate failed  error is "
                  << pcap_statustostr(ret) << "." << std::endl;
        return -1;
    }

    if (expression.length() > 0) {
        std::cout << StatisLogContext::getTimeString() << "Set pcap filter as \"" << expression << "\"." << std::endl;
        if (pcap_lookupnet(dev.c_str(), &net, &mask, _errbuf) == -1) {
            std::cerr << StatisLogContext::getTimeString() << " Call pcap_lookupnet failed, error is " << _errbuf << "."
                      << std::endl;
            return -1;
        }

        ret = pcap_compile(pcap_handle, &filter, expression.c_str(), 0, net);
        if (ret != 0) {
            std::cerr << StatisLogContext::getTimeString() << "Call pcap_compile failed, error is "
                      << pcap_statustostr(ret) << "." << std::endl;
            return -1;
        }

        ret = pcap_setfilter(pcap_handle, &filter);
        if (ret != 0) {
            std::cerr << StatisLogContext::getTimeString() << "Call pcap_setfilter failed, error is "
                      << pcap_statustostr(ret) << "." << std::endl;
            return -1;
        }
    }

    if (dumpfile) {
        if (openPcapDumper(pcap_handle) != 0) {
            std::cerr << StatisLogContext::getTimeString() << "Call openPcapDumper failed." << std::endl;
            return -1;
        }
    }
    pcapGuard.Dismiss();
    _pcap_handle = pcap_handle;
    return 0;
}
