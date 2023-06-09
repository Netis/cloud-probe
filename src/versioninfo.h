#ifndef PKTMINERG_VERSIONINFO_H
#define PKTMINERG_VERSIONINFO_H

static const int i1 = 100;

#include <pcap/pcap.h>
#include "version.h"

void showVersion() {
    std::cout << "~ pktminerg version " << std::string(PKTMINERG_VERSION) << " (rev: " <<
    std::string(PKTMINERG_GIT_COMMIT_HASH) << " build: " << std::string(PKTMINERG_BUILD_TIME) << ")" << std::endl;
    std::cout << "~ " << pcap_lib_version() << std::endl;
}

#endif //PKTMINERG_VERSIONINFO_H
