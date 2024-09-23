#ifndef SRC_PCAPEXPORT_H_
#define SRC_PCAPEXPORT_H_

#include <functional>
#include <iostream>

#include "log4cpp/Category.hh"
#include "log4cpp/FileAppender.hh"
#include "log4cpp/SimpleLayout.hh"
#include "log4cpp/PropertyConfigurator.hh"

#include "dep.h"
#include "logfilecontext.h"

#define PKTD_UNKNOWN -1
#define PKTD_IC 1
#define PKTD_OG 2
#define PKTD_NONCHECK 0
#define ETHER_TYPE_MPLS 0x8847

typedef struct
{
    uint8_t reserved1:4;
    uint8_t rra:4;
    uint8_t service_tag_h : 4;
    uint8_t reserved2 : 4;
    uint8_t service_tag_l:8;    
    uint8_t check;
}pa_tag_t;

typedef struct {
    uint32_t vx_flags;
    uint32_t vx_vni;
}vxlan_hdr_t;

static inline uint32_t
__rte_raw_cksum(const void *buf, size_t len, uint32_t sum)
{
    /* workaround gcc strict-aliasing warning */
    uintptr_t ptr = (uintptr_t)buf;
    typedef uint16_t u16_p;
    const u16_p *u16 = (const u16_p *)ptr;

    while (len >= (sizeof(*u16) * 4)) {
        sum += u16[0];
        sum += u16[1];
        sum += u16[2];
        sum += u16[3];
        len -= sizeof(*u16) * 4;
        u16 += 4;
    }
    while (len >= sizeof(*u16)) {
        sum += *u16;
        len -= sizeof(*u16);
        u16 += 1;
    }

    /* if length is in odd bytes */
    if (len == 1)
        sum += *((const uint8_t *)u16);

    return sum;
}

static inline uint16_t
__rte_raw_cksum_reduce(uint32_t sum)
{
    sum = ((sum & 0xffff0000) >> 16) + (sum & 0xffff);
    sum = ((sum & 0xffff0000) >> 16) + (sum & 0xffff);
    return (uint16_t)sum;
}

static inline uint16_t
rte_raw_cksum(const void *buf, size_t len)
{
    uint32_t sum;

    sum = __rte_raw_cksum(buf, len, 0x4a3b2d1c);
    return __rte_raw_cksum_reduce(sum);
}


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

typedef struct
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int reserved0:3; //MPLS Label
    unsigned int rra:4; //MPLS Label
    unsigned int magic_number: 1; //MPLS Label

    unsigned int service_tag_h:8; //MPLS Label

    unsigned int bottom:1; //MPLS Bottom of Label Stack
    unsigned int reserved1:3; //MPLS Experimental Bits;
    unsigned int service_tag_l:4; //MPLS Label

    unsigned int reserved2:8; //MPLS TTL
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned int magic_number: 1; //MPLS Label
    unsigned int rra:4; //MPLS Label
    unsigned int reserved0:3; //MPLS Label

    unsigned int service_tag_h:8; //MPLS Label

    unsigned int service_tag_l:4; //MPLS Label
    unsigned int reserved1:3; //MPLS Experimental Bits;
    unsigned int bottom:1; //MPLS Bottom of Label Stack

    unsigned int reserved2:8; //MPLS TTL
#endif
}mplsHdr;

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
                            if((us < tick_us)&&(tick_us - us) > 100000)  //traffic jitter
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
                            if((us < tick_us)&&(tick_us - us) > 100000) 
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
                            if((us < tick_us)&&(tick_us - us) > 100000) //traffic jitter
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

    static void makeExportFlag(void* data, int len, pa_tag_t* tag)
    {
        tag->check = static_cast<uint8_t>(rte_raw_cksum(data, len));
    }
    static bool checkExportFlag(void* data, int len, pa_tag_t* tag)
    {
        int check = tag->check;
        tag->check = 0;
        return htons(rte_raw_cksum(data, len)) == check;
    };

    virtual void checkSendBuf() {return;};
    virtual uint64_t getForwardCnt() {return 0;};
    virtual uint64_t getForwardByte() {return 0;};
};
#endif // SRC_PCAPEXPORT_H_
