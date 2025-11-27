## linux

```bash
wget https://github.com/the-tcpdump-group/libpcap/archive/refs/tags/libpcap-1.6.2.tar.gz
tar xzf libpcap-1.6.2.tar.gz
cd /path/to/unziped/dir
./configure --enable-dbus=no --without-libnl --prefix=$CLOUD_PROBE_CXX_LIBS_SDK/linux-amd64
make
make install
```

## macos

```bash
wget https://github.com/the-tcpdump-group/libpcap/archive/refs/tags/libpcap-1.6.2.tar.gz
tar xzf libpcap-1.6.2.tar.gz
cd /path/to/unziped/dir
./configure --disable-universal --prefix=$CLOUD_PROBE_CXX_LIBS_SDK/darwin-amd64
make
make install
```