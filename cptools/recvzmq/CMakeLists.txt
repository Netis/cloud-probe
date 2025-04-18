cmake_minimum_required(VERSION 3.10)
project(recvzmq C)

# 设置C标准
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if (NOT LIBRARY_ROOT)
    message(FATAL_ERROR "LIBRARY_ROOT is not set")
endif()

find_library(ZMQ_LIB libzmq.a PATHS ${LIBRARY_ROOT}/lib64 NO_DEFAULT_PATH)
if (NOT ZMQ_LIB)
    message(FATAL_ERROR "libzmq.a not found in ${LIBRARY_ROOT}/lib64")
endif()
message(STATUS "Using ZMQ_LIB: ${ZMQ_LIB}")

find_library(PCAP_LIB libpcap.a PATHS ${LIBRARY_ROOT}/lib NO_DEFAULT_PATH)
if (NOT PCAP_LIB)
    message(FATAL_ERROR "libpcap not found in ${LIBRARY_ROOT}/lib")
endif()
message(STATUS "Using PCAP_LIB: ${PCAP_LIB}")

# 添加可执行目标
add_executable(recvzmq main.c)

target_include_directories(recvzmq PRIVATE
    ${LIBRARY_ROOT}/include
)

target_link_libraries(recvzmq
    ${PCAP_LIB}
    ${ZMQ_LIB}
    pthread
    m
    stdc++
)
