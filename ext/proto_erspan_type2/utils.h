//
// Created by root on 11/21/19.
//

#ifndef PKTMINERG_UTILS_H
#define PKTMINERG_UTILS_H

#ifdef WIN32
    #include <WinSock2.h>
#else
    #include <arpa/inet.h>
#endif

class AddressV4V6 {
public:
    AddressV4V6();

    int buildAddr(const char* addr);
    int buildAddr(const char* addr, uint16_t port);

    struct sockaddr_in* getAddressV4() { return &svrAddr4_; }

    struct sockaddr_in6* getAddressV6() { return &svrAddr6_; }

    int getDomainAF_NET();

    struct sockaddr* getSockAddr();

    size_t getSockLen();

    bool isIpV6() { return sinFamily_ == AF_INET6; }
private:
    union {
        struct sockaddr_in svrAddr4_;
        struct sockaddr_in6 svrAddr6_;
    };
    uint16_t sinFamily_;
};

#endif //PKTMINERG_UTILS_H
