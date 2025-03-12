wget https://github.com/zeromq/libzmq/archive/refs/tags/v4.3.2.tar.gz
tar xzf v4.3.2.tar.gz
cd /path/to/unziped/dir
mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX:PATH=/root/cpagent_libs_sdk ..
sudo make -j4 install
