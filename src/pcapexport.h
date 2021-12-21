#ifndef SRC_PCAPEXPORT_H_
#define SRC_PCAPEXPORT_H_

#include <pcap/pcap.h>
#include <functional>
#include "dep.h"

#define PKTD_UNKNOWN -1
#define PKTD_IC 1
#define PKTD_OG 2
#define PKTD_NONCHECK 0

typedef struct
{
    uint8_t reserved1:4;
    uint8_t rra:4;
    uint8_t service_tag_h : 4;
    uint8_t reserved2 : 4;
    uint8_t service_tag_l:8;
    uint8_t check;
}pa_tag_t;

static inline uint64_t
tv2us(const timeval* tv)
{
    uint64_t us;

    us = tv->tv_usec;
    us += (tv->tv_sec * 1000000);

    return us;
}

enum class exporttype : uint8_t {
    gre = 0,
    file = 1,
    zmq = 2,
    vxlan = 3
};
#define __ETH_LEN 14
#define __GRE_LEN 8
#define __IP_LEN 20
#define __UDP_LEN 8
#define __VXLAN_LEN 8
#define __MTU 1500
#define __MTU_IP_PAYLOAD (__MTU - __IP_LEN)
#define __TRAFFIC_GAP_US 1000000
class PcapExportBase {
protected:
    std::function<int(uint64_t, int len)> _check_mbps_cb;
private:
    exporttype _type;
    double _Bpus;
    uint64_t _first_send_us;
    uint64_t _send_bytes;
protected:
    void setExportTypeAndMbps(exporttype type, double mbps)
    {
        _type = type;
        if(mbps == 0)
            _check_mbps_cb = [](uint64_t, int){ return 0; };
        else
        {
            _Bpus = mbps  / 8.0;
            //_Bpus = mbps / (1000 * 1000); //for pps
            _first_send_us = 0;
            _send_bytes = 0;

            switch (type) {
                case exporttype::vxlan:
                    _check_mbps_cb = [&](uint64_t us, int len){
                        if(!_first_send_us)
                            _first_send_us = us;
                        else
                        {
                            uint64_t tick_us;
                            uint64_t delta_us;

                            delta_us = (uint64_t)(_send_bytes / _Bpus);
                            tick_us = _first_send_us + delta_us;
                            if(us < tick_us)// && (tick_us - us) > 1000) //traffic jitter
                                return -1;
                            tick_us = _first_send_us + delta_us + __TRAFFIC_GAP_US; //traffic gap
                            if(us > tick_us)
                            {
                                _first_send_us = us;
                                _send_bytes = 0;
                            }
                        }
                        len += (__UDP_LEN + __VXLAN_LEN); //udp + vxlan
                        len += ((__ETH_LEN + __IP_LEN) * (len / __MTU_IP_PAYLOAD + ((len % __MTU_IP_PAYLOAD) ? 1 : 0))); //fragments append ethernet + ip
                        _send_bytes += len;
                        //++_send_bytes; //for pps
                        return 0;
                    };
                    break;
                case exporttype::gre:
                    _check_mbps_cb = [&](uint64_t us, int len){
                        if(!_first_send_us)
                            _first_send_us = us;
                        else
                        {
                            uint64_t tick_us;
                            uint64_t delta_us;

                            delta_us = (uint64_t)(_send_bytes / _Bpus);
                            tick_us = _first_send_us + delta_us;
                            if(us < tick_us)// && (tick_us - us) > 1000) //traffic jitter
                                return -1;
                            tick_us = _first_send_us + delta_us + __TRAFFIC_GAP_US; //traffic gap
                            if(us > tick_us)
                            {
                                _first_send_us = us;
                                _send_bytes = 0;
                            }
                        }
                        len += __GRE_LEN;//gre
                        len += ((__ETH_LEN + __IP_LEN) * (len / __MTU_IP_PAYLOAD + ((len % __MTU_IP_PAYLOAD) ? 1 : 0)));//fragments append ethernet + ip
                        _send_bytes += len;

                        //++_send_bytes; //for pps
                        return 0;
                    };
                    break;
                case exporttype::zmq:
                case exporttype::file:
                    _check_mbps_cb = [&](uint64_t us, int len){
                        if(!_first_send_us)
                            _first_send_us = us;
                        else
                        {
                            uint64_t tick_us;
                            uint64_t delta_us;

                            delta_us = (uint64_t)(_send_bytes / _Bpus);
                            tick_us = _first_send_us + delta_us;
                            if(us < tick_us)// && (tick_us - us) > 1000) //traffic jitter
                                return -1;
                            tick_us = _first_send_us + delta_us + __TRAFFIC_GAP_US; //traffic gap
                            if(us > tick_us)
                            {
                                _first_send_us = us;
                                _send_bytes = 0;
                            }
                        }
                        _send_bytes += len;
                        //++_send_bytes; //for pps
                        return 0;
                    };
                    break;
                default:
                    _check_mbps_cb = [](uint64_t, int){ return 0; };
                    break;
            }
        }
    }
public:
    exporttype getExportType() const {
        return _type;
    }
    virtual int initExport() = 0;
    virtual int exportPacket(const struct pcap_pkthdr *header, const uint8_t *pkt_data, int direct) = 0;
    virtual int closeExport() = 0;
};

#endif // SRC_PCAPEXPORT_H_
