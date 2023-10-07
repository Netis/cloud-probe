# Requirements

## Required operating systems

* CentOS 7.x or CentOS 8.x
* Debian 9.5
* SUSE 12 SP2
* Ubuntu 16.04
    
## Required compilers

* GCC 4.8.5 or higher
* CMake 3.3 or higher
    
## Required libraries

* libpcap-devel
* boost-devel
* boost-static


# Build steps

## CentOS and RedHat

1. Prepair the environment.

```shell
# install gcc
yum groupinstall "Development Tools"
# install cmake
yum -y install cmake
# install more required libraries
yum -y install libpcap-devel boost-devel boost-static

# build and install libzmq
wget https://github.com/zeromq/libzmq/archive/v4.3.2.zip
unzip v4.3.2.zip
cd /path/to/unziped/dir
mkdir build && cd build
cmake ..
sudo make -j4 install

# build and install cppzmq
wget https://github.com/zeromq/cppzmq/archive/v4.6.0.zip
unzip v4.6.0.zip
cd /path/to/unziped/dir
mkdir build && cd build
cmake -DCPPZMQ_BUILD_TESTS=OFF ..
sudo make -j4 install
```

2. Clone or download the project.
3. Go to the project folder and build it.

```shell
cd /path/to/packet-agent
mkdir build && cd build
cmake .. && make
```

4. Check output binaries. There should be four files in the *bin* folder.

```shell
ls ../bin
gredemo*     gredump*     pcapcompare* pktminerg*
```


## Debian and Ubuntu

1. Prepair the environment.

```shell
# install gcc
apt-get -y install build-essential
# install cmake
apt-get -y install cmake
# install more required libraries
apt-get -y install libpcap-dev libboost-all-dev

# build and install libzmq
wget https://github.com/zeromq/libzmq/archive/v4.3.2.zip
unzip v4.3.2.zip
cd /path/to/unziped/dir
mkdir build && cd build
cmake ..
sudo make -j4 install

# build and install cppzmq
wget https://github.com/zeromq/cppzmq/archive/v4.6.0.zip
unzip v4.6.0.zip
cd /path/to/unziped/dir
mkdir build && cd build
cmake -DCPPZMQ_BUILD_TESTS=OFF ..
sudo make -j4 install
```

2. Clone or download the project.
3. Go to the project folder and build it.

```shell
cd /path/to/packet-agent
mkdir build && cd build
cmake .. -DPLATFORM_DEBIAN=ON && make
```

4. Check output binaries. There should be four files in the *bin* folder.

```shell
ls ../bin
gredemo*     gredump*     pcapcompare* pktminerg*
```

## SUSE

1. Prepair the environment.

```shell
# install git
zypper -n install git-core
# install cmake
zypper -n install cmake
# install more required libraries
zypper -n install boost-devel
zypper -n si boost
cd /usr/src/packages/SOURCES/
tar --bzip2 -xf boost_1_54_0.tar.bz2
cd  boost_1_54_0/
./bootstrap.sh
./b2 install stage 

# build and install libzmq
wget https://github.com/zeromq/libzmq/archive/v4.3.2.zip
unzip v4.3.2.zip
cd /path/to/unziped/dir
mkdir build && cd build
cmake ..
sudo make -j4 install

# build and install cppzmq
wget https://github.com/zeromq/cppzmq/archive/v4.6.0.zip
unzip v4.6.0.zip
cd /path/to/unziped/dir
mkdir build && cd build
cmake -DCPPZMQ_BUILD_TESTS=OFF ..
sudo make -j4 install
```

2. Clone or download the project.
3. Go to the project folder and build it.

```shell
cd /path/to/packet-agent
rm -rf dep/unix/lib
mv dep/unix/suse12sp2lib  dep/unix/lib
mkdir build && cd build
cmake ..  && make
```

4. Check output binaries. There should be four files in the *bin* folder.

```shell
ls ../bin
gredemo*     gredump*     pcapcompare* pktminerg*
```
## FAQ

### CMake Error 51

```shell
CMake Error at /usr/local/Cellar/cmake/3.9.4/share/cmake/Modules/CMakeTestCCompiler.cmake:51 (message):
  The C compiler "/usr/bin/cc" is not able to compile a simple test program.
```

A: Firstly, check that [Xcode](https://developer.apple.com/xcode/) has been installed. Then make sure you have accepted the xcodebuild license.

```shell
sudo xcodebuild -license accept
```
  

