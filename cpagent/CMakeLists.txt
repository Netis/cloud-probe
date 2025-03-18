cmake_minimum_required(VERSION 3.10)
project(cpagent C)

option(ENABLE_DPDK "Enable DPDK support" OFF)
option(LINK_DYNAMIC_LIBPCAP "Link dynamic libpcap library" OFF)

# 设置C标准
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# 库安装的根目录
set(LIBRARY_ROOT "/root/cpagent_libs_sdk")

# 添加头文件搜索路径
include_directories(${LIBRARY_ROOT}/include src contrib)

# 添加库搜索路径
link_directories(${LIBRARY_ROOT}/lib ${LIBRARY_ROOT}/lib64)

# 查找libpcap
if(LINK_DYNAMIC_LIBPCAP)
    find_library(PCAP_LIB pcap PATHS ${LIBRARY_ROOT}/lib NO_DEFAULT_PATH)
else()
    find_library(PCAP_LIB libpcap.a PATHS ${LIBRARY_ROOT}/lib NO_DEFAULT_PATH)
endif()

if (NOT PCAP_LIB)
    message(FATAL_ERROR "libpcap not found in ${LIBRARY_ROOT}/lib")
endif()

# 查找libzmq
find_library(ZMQ_LIB libzmq.a PATHS ${LIBRARY_ROOT}/lib64 NO_DEFAULT_PATH)
if (NOT ZMQ_LIB)
    message(FATAL_ERROR "libzmq.a not found in ${LIBRARY_ROOT}/lib64")
endif()

# 查找DPDK
if(ENABLE_DPDK)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(LIBDPDK REQUIRED libdpdk)

    add_compile_definitions(ENABLE_DPDK)
endif()

# 获取所需的.c文件
file(GLOB SRC_FILES "src/*.c")
list(APPEND SRC_FILES "contrib/cJSON/cJSON.c")

# 排除DPDK相关文件
if(NOT ENABLE_DPDK)
    list(REMOVE_ITEM SRC_FILES "${CMAKE_CURRENT_SOURCE_DIR}/src/dpdk_pdump.c")
endif()

# 添加可执行目标
add_executable(cpagent ${SRC_FILES})

# 链接库（注意顺序）
target_link_libraries(cpagent
    ${LIBDPDK_STATIC_LDFLAGS}

    # 其他静态库
    ${PCAP_LIB}
    ${ZMQ_LIB}

    pthread
    # ZMQ需要的C++运行时
    stdc++
)
