## linux

```bash
wget https://github.com/zeromq/libzmq/archive/refs/tags/v4.3.3.tar.gz
tar xzf v4.3.3.tar.gz
cd /path/to/unziped/dir
mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX:PATH=$CLOUD_PROBE_CXX_LIBS_SDK/linux-amd64 ..
make -j4 install
```

## macos

```bash
wget https://github.com/zeromq/libzmq/archive/refs/tags/v4.3.3.tar.gz
tar xzf v4.3.3.tar.gz
cd /path/to/unziped/dir
mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX:PATH=$CLOUD_PROBE_CXX_LIBS_SDK/darwin-amd64 ..
make -j4 install
```
