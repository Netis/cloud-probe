//
// Created by root on 11/21/19.
//
#include <iostream>
#include <cstring>
#include <netdb.h>

#include "utils.h"

AddressV4V6::AddressV4V6() {
    sinFamily_ = AF_UNSPEC;
}

int AddressV4V6::buildAddr(const char* addr) {
    char ip[128];
    memset(ip, 0, sizeof(ip));
    strcpy(ip, addr);

    socklen_t maxLen = 128;

    struct addrinfo *result;
    int ret = getaddrinfo(ip, NULL, NULL, &result);
    if (ret != 0) {
        std::cerr << "proto_vxlan: getaddrinfo failed, ip is " << addr << std::endl;
        return ret;
    }
    struct sockaddr *sa = result->ai_addr;

    sinFamily_ = sa->sa_family;
    switch(sa->sa_family) {
        case AF_INET:
            inet_ntop(AF_INET, &((reinterpret_cast<struct sockaddr_in*>(sa))->sin_addr), ip, maxLen);
            svrAddr4_.sin_family = AF_INET;
            svrAddr4_.sin_addr.s_addr = inet_addr(ip);
            break;
        case AF_INET6:
            inet_ntop(AF_INET6, &((reinterpret_cast<struct sockaddr_in6*>(sa))->sin6_addr), ip, maxLen);
            memset(&svrAddr6_, 0, sizeof(svrAddr6_));
            svrAddr6_.sin6_family = AF_INET6;
            if (inet_pton(AF_INET6, ip, &svrAddr6_.sin6_addr) < 0 ) {
                std::cerr << "proto_vxlan: inet_pton failed, ip is " << addr << std::endl;
                ret = -1;
            }
            break;
        default:
            std::cerr << "proto_vxlan: Unsupport sa_family: " << sa->sa_family << std::endl;
            ret = -2;
    }
    freeaddrinfo(result);
    return ret;
}

int AddressV4V6::buildAddr(const char* addr, uint16_t port) {
    int ret = buildAddr(addr);
    if (ret) {
        return ret;
    }
    switch (sinFamily_) {
        case AF_INET:
            svrAddr4_.sin_port = htons(port);
            break;
        case AF_INET6:
            svrAddr6_.sin6_port = htons(port);
            break;
        default:
            break;
    }
    return 0;
}

int AddressV4V6::getDomainAF_NET() {
    return isIpV6() ? AF_INET6 : AF_INET;
}

struct sockaddr* AddressV4V6::getSockAddr() {
    return isIpV6() ? (struct sockaddr*)(getAddressV6()) : (struct sockaddr*)(getAddressV4());
}

size_t AddressV4V6::getSockLen() {
    return isIpV6() ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
}
