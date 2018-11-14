# Requirements

## Required operating systems

* CentOS 6.x or CentOS 7.x
* Debian 9.5
* SUSE 12.2
* Ubuntu 16.04
* Mac OS X (experimental)
    
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
zypper -n install libpcap-devel boost-devel
zypper -n si boost
cd /usr/src/packages/SOURCES/
tar --bzip2 -xf boost_1_54_0.tar.bz2
cd  boost_1_54_0/
./bootstrap.sh
./b2 install stage 
```

2. Clone or download the project.
3. Go to the project folder and build it.

```shell
cd /path/to/packet-agent
mkdir build && cd build
cmake ..  && make
```

4. Check output binaries. There should be four files in the *bin* folder.

```shell
ls ../bin
gredemo*     gredump*     pcapcompare* pktminerg*
```
## Mac OS X

1. Install [Xcode](https://developer.apple.com/xcode/).
2. Download the latest release of libpcap from [tcpdump site](http://www.tcpdump.org). Extract the zip, enter the folder and build the library.

```shell
cd /path/to/libpcap
./configure 
make
make install
# Check that libpcap.a and libpcap.dylib exist.
ls /usr/local/lib/libpcap*
```

2. *Recommended*: install [brew](https://brew.sh/) for easier package management.

```shell
# install boost
brew install boost
```

2. Clone or download the project.
3. Build the project.

```shell
cd /path/to/packet-agent
mkdir build && cd build
cmake .. && make
```

4. Ensure the build is successful. The *bin* folder should contain four binary files.

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
  

