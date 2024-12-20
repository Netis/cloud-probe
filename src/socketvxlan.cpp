#include "socketvxlan.h"
#include "statislog.h"
#include <cstdint>
#include <cstring>
#include <iostream>
const int INVALIDE_SOCKET_FD = -1;

PcapExportVxlan::PcapExportVxlan(const std::vector<std::string> &remoteips,
                                 uint32_t vni, const std::string &bind_device,
                                 const int pmtudisc, const int vxlan_port,
                                 double mbps, uint8_t vni_version,
                                 LogFileContext &ctx, int capTime)
    : _remoteips(remoteips), _vni(vni), _vni_version(vni_version),
      _vxlan_port(vxlan_port), _bind_device(bind_device), _pmtudisc(pmtudisc),
      _socketfds(remoteips.size()), _remote_addrs(remoteips.size()),
      _vxlanbuffers(remoteips.size()), _ctx(ctx), _capTime(capTime) {
  setExportTypeAndMbps(exporttype::vxlan, mbps);
  for (size_t i = 0; i < remoteips.size(); ++i) {
    _socketfds[i] = INVALIDE_SOCKET_FD;
    _vxlanbuffers[i].resize(65535 + sizeof(vxlan_hdr_t), '\0');
  }
}

PcapExportVxlan::~PcapExportVxlan() { closeExport(); }

int PcapExportVxlan::initSockets(size_t index, uint32_t vni) {
  auto &socketfd = _socketfds[index];
  auto &vxlanbuffer = _vxlanbuffers[index];

  vxlan_hdr_t hdr;
  if (socketfd == INVALIDE_SOCKET_FD) {
    hdr.vx_flags = htonl(0x08000000);
    hdr.vx_vni = (htonl(vni << 8));
    std::memcpy(reinterpret_cast<void *>(&(vxlanbuffer[0])), &hdr,
                sizeof(vxlan_hdr_t));

    _remote_addrs[index].sin_family = AF_INET;
    _remote_addrs[index].sin_port = htons(_vxlan_port);
    inet_pton(AF_INET, _remoteips[index].c_str(),
              &_remote_addrs[index].sin_addr.s_addr);

    if ((socketfd = socket(AF_INET, SOCK_DGRAM, 0)) == INVALIDE_SOCKET_FD) {
      output_buffer = std::string("Create socket failed, error code is ") +
                      std::to_string(errno) + ", error is " + strerror(errno) +
                      ".";
      _ctx.log(output_buffer, log4cpp::Priority::ERROR);
      std::cerr << StatisLogContext::getTimeString() << output_buffer
                << std::endl;
      return -1;
    }

    if (_bind_device.length() > 0) {
#ifdef WIN32
      // TODO: bind device on WIN32
#else
      if (setsockopt(socketfd, SOL_SOCKET, SO_BINDTODEVICE,
                     _bind_device.c_str(), _bind_device.length()) < 0) {
        output_buffer = std::string("SO_BINDTODEVICE failed, error code is ") +
                        std::to_string(errno) + ", error is " +
                        strerror(errno) + ".";
        _ctx.log(output_buffer, log4cpp::Priority::ERROR);
        std::cerr << StatisLogContext::getTimeString() << output_buffer
                  << std::endl;
        return -1;
      }
#endif // WIN32
    }

#ifdef WIN32
    // TODO: bind device on WIN32
#else
    if (_pmtudisc >= 0) {
      if (setsockopt(socketfd, SOL_IP, IP_MTU_DISCOVER, &_pmtudisc,
                     sizeof(_pmtudisc)) == -1) {
        output_buffer = std::string("IP_MTU_DISCOVER failed, error code is ") +
                        std::to_string(errno) + ", error is " +
                        strerror(errno) + ".";
        _ctx.log(output_buffer, log4cpp::Priority::ERROR);
        std::cerr << StatisLogContext::getTimeString() << output_buffer
                  << std::endl;
        return -1;
      }
    }
#endif // WIN32
  }
  return 0;
}

int PcapExportVxlan::initExport() {
  for (size_t i = 0; i < _remoteips.size(); ++i) {
    int ret = initSockets(i, _vni);
    if (ret != 0) {
      output_buffer = std::string("Failed with index: ") + std::to_string(i);
      _ctx.log(output_buffer, log4cpp::Priority::ERROR);
      std::cerr << output_buffer << std::endl;
      return ret;
    }
  }
  return 0;
}

int PcapExportVxlan::closeExport() {
  for (size_t i = 0; i < _remoteips.size(); ++i) {
    if (_socketfds[i] != INVALIDE_SOCKET_FD) {
      socket_close(_socketfds[i]);
      _socketfds[i] = INVALIDE_SOCKET_FD;
    }
  }
  return 0;
}

int PcapExportVxlan::exportPacket(const struct pcap_pkthdr *header,
                                  const uint8_t *pkt_data, int direct) {
  int ret = 0;
  uint64_t us;
  // direct = 0;
  if (direct == PKTD_UNKNOWN)
    return -1;

  us = tv2us(&header->ts);
  if (_check_mbps_cb(us, header->caplen) < 0)
    return -1;

  for (size_t i = 0; i < _remoteips.size(); ++i) {
    ret |= exportPacket(i, header, pkt_data, direct);
  }
  return ret;
}

int PcapExportVxlan::exportPacket(size_t index,
                                  const struct pcap_pkthdr *header,
                                  const uint8_t *pkt_data, int direct) {
  (void)direct;

  auto &vxlanbuffer = _vxlanbuffers[index];
  socket_t socketfd = _socketfds[index];
  auto &remote_addr = _remote_addrs[index];

  size_t length = (size_t)(header->caplen <= 65535 ? header->caplen : 65535);

  vxlan_hdr_t *hdr;
  hdr = (vxlan_hdr_t *)&*vxlanbuffer.begin();
  std::memcpy(reinterpret_cast<void *>(&(vxlanbuffer[sizeof(vxlan_hdr_t)])),
              reinterpret_cast<const void *>(pkt_data), length);
  uint32_t tv_sec = htonl(header->ts.tv_sec);
  //注意：通过libpcap获取的捕获时间精度为微秒，而数据包中附加的时间为纳秒，所以需要*1000
  uint32_t tv_nsec = htonl(header->ts.tv_usec*1000);
  std::cout << "====got time" << header->ts.tv_usec<< std::endl;
  if (_capTime == 1) {
    memcpy(
        reinterpret_cast<void *>(&(vxlanbuffer[sizeof(vxlan_hdr_t)]) + length),
        &tv_sec, sizeof(uint32_t));
    length += 4;
    memcpy(
        reinterpret_cast<void *>(&(vxlanbuffer[sizeof(vxlan_hdr_t)]) + length),
        &tv_nsec, sizeof(uint32_t));
    length += 4;
  }
  if (_vni_version == 1) {
    hdr->vx_vni = htonl(_vni << 8);
    if (direct != 0) {
      ((pa_tag_t *)&hdr->vx_vni)->rra = direct;
      ((pa_tag_t *)&hdr->vx_vni)->reserved1 = 0;
      ((pa_tag_t *)&hdr->vx_vni)->reserved2 = 0;
      ((pa_tag_t *)&hdr->vx_vni)->check = 0;
    }
    makeExportFlag(hdr,
                   sizeof(vxlan_hdr_t) + sizeof(ether_header) + sizeof(iphdr),
                   (pa_tag_t *)&hdr->vx_vni);
  } else {
    hdr->vx_vni = htonl(_vni + direct);
  }

  ssize_t nSend =
      sendto(socketfd, &(vxlanbuffer[0]), int(length + sizeof(vxlan_hdr_t)), 0,
             (struct sockaddr *)&remote_addr, sizeof(struct sockaddr_in));
  while (nSend == -1 && errno == ENOBUFS) {
    usleep(1000);
    nSend = static_cast<int>(
        sendto(socketfd, &(vxlanbuffer[0]), int(length + sizeof(vxlan_hdr_t)),
               0, (struct sockaddr *)&remote_addr, sizeof(struct sockaddr)));
  }
  if (nSend == -1) {
    output_buffer = std::string("Send to socket failed, error code is ") +
                    std::to_string(errno) + ", error is " + strerror(errno) +
                    ".";
    _ctx.log(output_buffer, log4cpp::Priority::ERROR);
    std::cerr << StatisLogContext::getTimeString() << output_buffer
              << std::endl;
    return -1;
  }
  if (nSend < (ssize_t)(length + sizeof(vxlan_hdr_t))) {
    output_buffer = std::string("Send socket ") +
                    std::to_string(length + sizeof(vxlan_hdr_t)) +
                    " bytes, but only " + std::to_string(nSend) +
                    " bytes are sent success.";
    _ctx.log(output_buffer, log4cpp::Priority::ERROR);
    std::cerr << StatisLogContext::getTimeString() << output_buffer
              << std::endl;
    return 1;
  }
  return 0;
}
