wget https://github.com/the-tcpdump-group/libpcap/archive/refs/tags/libpcap-1.5.3.tar.gz
tar xzf libpcap-1.5.3.tar.gz
cd libpcap-libpcap-1.5.3
./configure --prefix=/root/cpagent_libs_sdk
make
make install
