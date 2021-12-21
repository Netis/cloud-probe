//
// Created by Haibo.Fu on 2021/3/11.
//

#ifndef PKTMINERG_DEF_H
#define PKTMINERG_DEF_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <unordered_map>
#include <sys/types.h>
struct tcphdr
  {
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack_seq;
#  if __BYTE_ORDER == __LITTLE_ENDIAN
    uint16_t res1:4;
    uint16_t doff:4;
    uint16_t fin:1;
    uint16_t syn:1;
    uint16_t rst:1;
    uint16_t psh:1;
    uint16_t ack:1;
    uint16_t urg:1;
    uint16_t res2:2;
#  elif __BYTE_ORDER == __BIG_ENDIAN
    uint16_t doff:4;
    uint16_t res1:4;
    uint16_t res2:2;
    uint16_t urg:1;
    uint16_t ack:1;
    uint16_t psh:1;
    uint16_t rst:1;
    uint16_t syn:1;
    uint16_t fin:1;
#  else
#   error "Adjust your <bits/endian.h> defines"
#  endif
    u_int16_t window;
    u_int16_t check;
    u_int16_t urg_ptr;
};

struct udphdr
{
  uint16_t source;
  uint16_t dest;
  uint16_t len;
  uint16_t check;
};
#ifdef WIN32

#include <WinSock2.h>
#include <BaseTsd.h>
#include <windows.h>
#include <iphlpapi.h>

#define usleep Sleep
#define IPPROTO_GRE 47
#define __BYTE_ORDER __BIG_ENDIAN
#define ETH_ALEN	6		/* Octets in one ethernet addr	 */
#define	ETHERTYPE_IP		0x0800		/* IP */
#define	ETHERTYPE_IPV6		0x86dd		/* IP protocol version 6 */
#define	ETHERTYPE_VLAN		0x8100		/* IEEE 802.1Q VLAN tagging */

typedef SOCKET socket_t;
typedef SSIZE_T ssize_t;

struct ether_header
{
    uint8_t  ether_dhost[ETH_ALEN];	/* destination eth addr	*/
    uint8_t  ether_shost[ETH_ALEN];	/* source ether addr	*/
    uint16_t ether_type;		        /* packet type ID field	*/
};
struct iphdr
{
    uint8_t version:4;
    uint8_t ihl:4;
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
    /*The options start here. */
};

struct ip6_hdr
{
    union
    {
        struct ip6_hdrctl
        {
            uint32_t ip6_un1_flow;   /* 4 bits version, 8 bits TC,
                        20 bits flow-ID */
            uint16_t ip6_un1_plen;   /* payload length */
            uint8_t  ip6_un1_nxt;    /* next header */
            uint8_t  ip6_un1_hlim;   /* hop limit */
        } ip6_un1;
        uint8_t ip6_un2_vfc;       /* 4 bits version, top 4 bits tclass */
    } ip6_ctlun;
    struct in6_addr ip6_src;      /* source address */
    struct in6_addr ip6_dst;      /* destination address */
};

#define socket_close(fd) shutdown(fd, SD_BOTH)
#define inet_pton InetPton

inline int gettimeofday(struct timeval* tp, void* tzp)
{
    time_t clock;
    struct tm tm;
    SYSTEMTIME wtm;
    GetLocalTime(&wtm);
    tm.tm_year = wtm.wYear - 1900;
    tm.tm_mon = wtm.wMonth - 1;
    tm.tm_mday = wtm.wDay;
    tm.tm_hour = wtm.wHour;
    tm.tm_min = wtm.wMinute;
    tm.tm_sec = wtm.wSecond;
    tm.tm_isdst = -1;
    clock = mktime(&tm);
    tp->tv_sec = (long)clock;
    tp->tv_usec = wtm.wMilliseconds * 1000;
    return (0);
}

inline std::string u16ToUtf8(const std::wstring& u16)
{
    std::string utf8;
    int len;

    len = WideCharToMultiByte(CP_UTF8, 0, u16.c_str(), -1, 0, 0, 0, 0);
    utf8.resize(len);
    ::WideCharToMultiByte(CP_UTF8, 0, u16.c_str(), -1, (char*)utf8.c_str(), len, 0, 0);
    return utf8;
}

inline std::string u16ToGb2312(const std::wstring& u16)
{
    std::string gb2312;
    int len;

    len = WideCharToMultiByte(CP_ACP, 0, u16.c_str(), -1, 0, 0, 0, 0);
    gb2312.resize(len);
    ::WideCharToMultiByte(CP_ACP, 0, u16.c_str(), -1, (char*)gb2312.c_str(), len, 0, 0);
    return gb2312;
}

inline std::wstring utf8ToU16(const std::string& utf8)
{
    std::wstring u16;
    int len;

    len = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, NULL, 0);
    u16.resize(len);
    ::MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, (LPWSTR)u16.c_str(), len);
    return u16;
}

inline std::wstring gb2312ToU16(const std::string& utf8)
{
    std::wstring u16;
    int len;
    len = MultiByteToWideChar(CP_ACP, 0, utf8.c_str(), -1, NULL, 0);
    u16.resize(len);
    ::MultiByteToWideChar(CP_ACP, 0, utf8.c_str(), -1, (LPWSTR)u16.c_str(), len);
    return u16;
}


inline int gethexdigit(const char* p)
{
    if (*p >= '0' && *p <= '9') {
        return *p - '0';
    }
    else if (*p >= 'A' && *p <= 'F') {
        return *p - 'A' + 0xA;
    }
    else if (*p >= 'a' && *p <= 'f') {
        return *p - 'a' + 0xa;
    }
    else {
        return -1; /* Not a hex digit */
    }
}

inline int get8hexdigits(const char* p, DWORD* d)
{
    int digit;
    DWORD val;
    int i;

    val = 0;
    for (i = 0; i < 8; i++) {
        digit = gethexdigit(p++);
        if (digit == -1) {
            return -1; /* Not a hex digit */
        }
        val = (val << 4) | digit;
    }
    *d = val;
    return 0;
}

inline int get4hexdigits(const char* p, WORD* w)
{
    int digit;
    WORD val;
    int i;

    val = 0;
    for (i = 0; i < 4; i++) {
        digit = gethexdigit(p++);
        if (digit == -1) {
            return -1; /* Not a hex digit */
        }
        val = (val << 4) | digit;
    }
    *w = val;
    return 0;
}

inline int parse_as_guid(const char* guid_text, GUID* guid)
{
    int i;
    int digit1, digit2;

    if (*guid_text != '{') {
        return -1; /* Nope, not enclosed in {} */
    }
    guid_text++;
    /* There must be 8 hex digits; if so, they go into guid->Data1 */
    if (get8hexdigits(guid_text, &guid->Data1) < 0) {
        return -1; /* nope, not 8 hex digits */
    }
    guid_text += 8;
    /* Now there must be a hyphen */
    if (*guid_text != '-') {
        return -1; /* Nope */
    }
    guid_text++;
    /* There must be 4 hex digits; if so, they go into guid->Data2 */
    if (get4hexdigits(guid_text, &guid->Data2) < 0) {
        return -1; /* nope, not 4 hex digits */
    }
    guid_text += 4;
    /* Now there must be a hyphen */
    if (*guid_text != '-') {
        return -1; /* Nope */
    }
    guid_text++;
    /* There must be 4 hex digits; if so, they go into guid->Data3 */
    if (get4hexdigits(guid_text, &guid->Data3) < 0) {
        return -1; /* nope, not 4 hex digits */
    }
    guid_text += 4;
    /* Now there must be a hyphen */
    if (*guid_text != '-') {
        return -1; /* Nope */
    }
    guid_text++;
    /*
     * There must be 4 hex digits; if so, they go into the first 2 bytes
     * of guid->Data4.
     */
    for (i = 0; i < 2; i++) {
        digit1 = gethexdigit(guid_text);
        if (digit1 == -1) {
            return -1; /* Not a hex digit */
        }
        guid_text++;
        digit2 = gethexdigit(guid_text);
        if (digit2 == -1) {
            return -1; /* Not a hex digit */
        }
        guid_text++;
        guid->Data4[i] = (digit1 << 4) | (digit2);
    }
    /* Now there must be a hyphen */
    if (*guid_text != '-') {
        return -1; /* Nope */
    }
    guid_text++;
    /*
     * There must be 12 hex digits; if so,t hey go into the next 6 bytes
     * of guid->Data4.
     */
    for (i = 0; i < 6; i++) {
        digit1 = gethexdigit(guid_text);
        if (digit1 == -1) {
            return -1; /* Not a hex digit */
        }
        guid_text++;
        digit2 = gethexdigit(guid_text);
        if (digit2 == -1) {
            return -1; /* Not a hex digit */
        }
        guid_text++;
        guid->Data4[i + 2] = (digit1 << 4) | (digit2);
    }
    /* Now there must be a closing } */
    if (*guid_text != '}') {
        return -1; /* Nope */
    }
    guid_text++;
    /* And that must be the end of the string */
    if (*guid_text != '\0') {
        return -1; /* Nope */
    }
    return 0;
}


inline int
get_interface_friendly_name_from_device_guid(__in GUID* guid, std::string* friendly_name)
{
    HRESULT hr;

    /* Need to convert an Interface GUID to the interface friendly name (e.g. "Local Area Connection")
    * The functions required to do this all reside within iphlpapi.dll
    */

    NET_LUID InterfaceLuid;
    hr = ConvertInterfaceGuidToLuid(guid, &InterfaceLuid);
    if (hr == NO_ERROR) {
        /* guid->luid success */
        WCHAR wName[NDIS_IF_MAX_STRING_SIZE + 1];
        hr = ConvertInterfaceLuidToAlias(&InterfaceLuid, wName, NDIS_IF_MAX_STRING_SIZE + 1);
        if (hr == NO_ERROR) {
            *friendly_name = u16ToUtf8(wName);
            return 0;
        }
    }
    return -1;
}

inline int getLocalInterfacesWin(std::unordered_map<std::string, std::string>& interfaces)
{
#if 0
    PIP_ADAPTER_ADDRESSES addrs;
    ULONG addrsLen;
    PIP_ADAPTER_ADDRESSES addr;
    ULONG ret;

    addrsLen = 150000;
    if (!(addrs = (IP_ADAPTER_ADDRESSES*)malloc(addrsLen)))
        return -1;

    if ((ret = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_ALL_COMPARTMENTS, NULL, addrs, &addrsLen)) != NO_ERROR)
    {
        fprintf(stderr, "GetAdaptersAddresses failed: %d\n", ret);
        free(addrs);
        return -1;
    }

    addr = addrs;
    while (addr) {
        interfaces.emplace(u16ToUtf8(addr->FriendlyName), addr->AdapterName);
        addr = addr->Next;
    }
    free(addrs);
    return 0;
#else
    pcap_if_t* all_devs, * it;
    char err_buf[PCAP_ERRBUF_SIZE];
    //all_devs = 0;
    if (pcap_findalldevs(&all_devs, err_buf) < 0)
    {
        fprintf(stderr, "pcap_findalldevs failed: %s\n", err_buf);
        return -1;
    }
    for (it = all_devs; it; it = it->next)
    {
        std::string friendly_name;
        GUID guid;
        parse_as_guid(it->name + 12, &guid);
        if (get_interface_friendly_name_from_device_guid(&guid, &friendly_name) < 0)
            continue;
        interfaces.emplace(friendly_name, it->name);
    }
    return 0;
#endif
}

#else

#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <bits/endian.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <dirent.h>

typedef int socket_t;
#define socket_close(fd) close(fd)

#endif

#endif //PKTMINERG_DEF_H
