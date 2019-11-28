cmake_minimum_required(VERSION 3.5)
project(proto_erspan_type1)


set(PLUGIN_MAJOR_VERSION "0")
set(PLUGIN_MINOR_VERSION "0")
set(PLUGIN_PATCH_VERSION "1")
set(PLUGIN_VERSION_STRING "${PLUGIN_MAJOR_VERSION}.${PLUGIN_MINOR_VERSION}.${PLUGIN_PATCH_VERSION}")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/../../bin)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/../../bin)

include_directories(../../include)

set(SOURCE_FILES main.cpp)
add_library(proto_erspan_type1 SHARED ${SOURCE_FILES})
