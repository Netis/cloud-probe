#include <pcap/pcap.h>
#include <string>
const char *pcap_statustostr(int) {
	static std::string message("unknown.");
	return message.c_str();
}