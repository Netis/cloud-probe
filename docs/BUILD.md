# Prerequisites

## Required Operating System

* Linux (e.g., CentOS 7.9, Ubuntu 22.04, etc.)

## Required Compilers

* GCC 4.8.5 or later
* CMake 3.10 or later
* Golang 1.24 or later

## Install Dependency Libraries

Set the root directory for installing dependencies:
`export CLOUD_PROBE_CXX_LIBS_SDK=/opt/cloud-probe-cxx-libs-sdk`

### Install libpcap
```bash
wget https://github.com/the-tcpdump-group/libpcap/archive/refs/tags/libpcap-1.6.2.tar.gz
tar xzf libpcap-1.6.2.tar.gz
cd /path/to/unzipped/dir
./configure --prefix=$CLOUD_PROBE_CXX_LIBS_SDK/linux-amd64
make
make install
```

### Install libzmq
```bash
wget https://github.com/zeromq/libzmq/archive/refs/tags/v4.3.3.tar.gz
tar xzf v4.3.3.tar.gz
cd /path/to/unziped/dir
mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX:PATH=$CLOUD_PROBE_CXX_LIBS_SDK/linux-amd64 ..
make -j4 install
```

## Build cloud-probe

Clone the repository
```bash
git clone https://github.com/Netis/cloud-probe.git
```

Set environment variables
```bash
export CLOUD_PROBE_VERSION=0.9.0
export CPWORKER_LIBRARY_ROOT=/opt/cloud-probe-cxx-libs-sdk/linux-amd64
```

Execute build commands
```bash
cd ./cloud-probe/build
go run mage.go build:linux
```

The successfully built binary package will be output to:
`./cloud-probe/build/dist/cloud-probe-0.9.0-linux-amd64.tar.gz`
