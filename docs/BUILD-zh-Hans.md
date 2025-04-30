# 前置要求

## 所需操作系统

* Linux (比如: Centos7.9, Ubuntu22.04等)

## 所需编译器

* GCC 4.8.5 或更高
* CMake 3.10 或更高
* Golang 1.24 或更高

## 安装依赖库

设置依赖库安装根目录:
`export CLOUD_PROBE_CXX_LIBS_SDK=/opt/cloud-probe-cxx-libs-sdk`

### 安装libpcap
```bash
wget https://github.com/the-tcpdump-group/libpcap/archive/refs/tags/libpcap-1.6.2.tar.gz
tar xzf libpcap-1.6.2.tar.gz
cd /path/to/unziped/dir
./configure --prefix=$CLOUD_PROBE_CXX_LIBS_SDK/linux-amd64
make
make install
```

### 安装libzmq
```bash
wget https://github.com/zeromq/libzmq/archive/refs/tags/v4.3.3.tar.gz
tar xzf v4.3.3.tar.gz
cd /path/to/unziped/dir
mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX:PATH=$CLOUD_PROBE_CXX_LIBS_SDK/linux-amd64 ..
make -j4 install
```

## 构建cloud-probe

克隆代码
```bash
git clone https://github.com/Netis/cloud-probe.git
```

设置环境变量
```bash
export CLOUD_PROBE_VERSION=0.9.0
export CPWORKER_LIBRARY_ROOT=/opt/cloud-probe-cxx-libs-sdk/linux-amd64
```

执行构建命令
```bash
cd ./cloud-probe/build
go run mage.go build:linux
```

构建成功后输出二进制包:
`./cloud-probe/build/dist/cloud-probe-0.9.0-linux-amd64.tar.gz`
