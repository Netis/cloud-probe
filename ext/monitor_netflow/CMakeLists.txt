cmake_minimum_required(VERSION 2.8)
project(monitor_netflow)


set(PLUGIN_MAJOR_VERSION "0")
set(PLUGIN_MINOR_VERSION "1")
set(PLUGIN_PATCH_VERSION "0")
set(PLUGIN_VERSION_STRING "${PLUGIN_MAJOR_VERSION}.${PLUGIN_MINOR_VERSION}.${PLUGIN_PATCH_VERSION}")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/../../bin)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/../../bin)

include_directories(../../include)
include_directories(./fprobe-1.1/src)


set(FPROBE_DIR ${PROJECT_SOURCE_DIR}/fprobe-1.1/src)
set(SOURCE_FILES_FPROBE ${FPROBE_DIR}/fprobe.c
        ${FPROBE_DIR}/fprobe.c
        ${FPROBE_DIR}/hash.c
        ${FPROBE_DIR}/mem.c
        ${FPROBE_DIR}/my_getopt.c
        ${FPROBE_DIR}/my_log.c
        ${FPROBE_DIR}/netflow.c)

set(SOURCE_FILES main.cpp ${SOURCE_FILES_FPROBE})
add_library(monitor_netflow SHARED ${SOURCE_FILES})
target_link_libraries(monitor_netflow pthread pcap)