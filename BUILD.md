# Requirements

## Required Operating Systems
* CentOS 6.x or CentOS 7.x
* Mac OS X (experimental)
    
## Required compilers
* GCC 4.8.5 or higher
* CMake 3.3 or higher
    
## Required libraries
* libpcap-devel
* boost-devel
* boost-static

# Build on CentOS
## Build steps 
1. Perpair the environment.
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

# Build on Mac OS X
## Build steps
1. Perpair the environment. You should install [Xcode](https://developer.apple.com/xcode/) first. 
2. Download the latest release for libpcap form [tcpdump stie](http://www.tcpdump.org). Extract the zip.
```shell
cd /path/to/libpcap
./configure 
make
make install
# Check that libpcap.a and libpcap.dylib exists.
ls /usr/local/lib/libpcap*
```
2. And then, we recommend your to install [brew](https://brew.sh/) for easier package management.
```shell
# install brootstrap
brew install brootstrap
```
2. Clone or download the project.
3. Build the project.
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
## FAQ Troubles in building
* Q: CMake Error 51
```shell
CMake Error at /usr/local/Cellar/cmake/3.9.4/share/cmake/Modules/CMakeTestCCompiler.cmake:51 (message):
  The C compiler "/usr/bin/cc" is not able to compile a simple test program.
```
	* A: To solve this problem, first your should check that [Xcode](https://developer.apple.com/xcode/) has been installed on your machine. And then make sure the accept the  xcodebuild license.
	```shell
	sudo xcodebuild -license accept
	```
  

