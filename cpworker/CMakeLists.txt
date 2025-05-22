cmake_minimum_required(VERSION 3.10)

project(cpworker VERSION "0.9.0" LANGUAGES C)

option(ENABLE_DPDK "Enable DPDK support" OFF)
option(ENABLE_LINK_STATIC_LIBPCAP "Enable link static libpcap library" OFF)
option(ENABLE_UNIT_TESTS "Enable building unit test" ON)

# 设置C标准
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# 初始化所有标识为 0
set(OS_WINDOWS 0)
set(OS_UNIX 0)
set(OS_BSD 0)
set(OS_LINUX 0)
set(OS_MACOS 0)
set(OS_FREEBSD 0)
set(OS_OPENBSD 0)
set(OS_NETBSD 0)

# 操作系统检测逻辑
if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    set(OS_WINDOWS 1)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(OS_UNIX 1)
    set(OS_LINUX 1)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    set(OS_UNIX 1)
    set(OS_MACOS 1)
elseif(CMAKE_SYSTEM_NAME MATCHES ".*BSD$")
    set(OS_UNIX 1)
    set(OS_BSD 1)

    if(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
        set(OS_FREEBSD 1)
    elseif(CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
        set(OS_OPENBSD 1)
    elseif(CMAKE_SYSTEM_NAME STREQUAL "NetBSD")
        set(OS_NETBSD 1)
    endif()
endif()

execute_process(
    COMMAND git rev-parse --short HEAD
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    OUTPUT_VARIABLE GIT_COMMIT_HASH
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
message("git commit hash: " ${GIT_COMMIT_HASH})

if (NOT DEFINED CPWORKER_VERSION)
    set(CPWORKER_VERSION PROJECT_VERSION)
endif()

configure_file(build_config.h.in ${CMAKE_BINARY_DIR}/build_config.h @ONLY)

# 库安装的根目录
if (NOT LIBRARY_ROOT)
    message(FATAL_ERROR "LIBRARY_ROOT is not set")
endif()

# 查找libpcap
if(ENABLE_LINK_STATIC_LIBPCAP)
    find_library(PCAP_LIB libpcap.a PATHS ${LIBRARY_ROOT}/lib NO_DEFAULT_PATH)
else()
    find_library(PCAP_LIB pcap PATHS ${LIBRARY_ROOT}/lib NO_DEFAULT_PATH)
endif()

if (NOT PCAP_LIB)
    message(FATAL_ERROR "libpcap not found in ${LIBRARY_ROOT}/lib")
endif()
message(STATUS "Using PCAP_LIB: ${PCAP_LIB}")

# 查找libzmq
find_library(
    ZMQ_LIB
    libzmq.a
    PATHS ${LIBRARY_ROOT}/lib64 ${LIBRARY_ROOT}/lib
    NO_DEFAULT_PATH
)
if (NOT ZMQ_LIB)
    message(FATAL_ERROR "libzmq.a not found in ${LIBRARY_ROOT}/lib64 or ${LIBRARY_ROOT}/lib")
endif()
message(STATUS "Using ZMQ_LIB: ${ZMQ_LIB}")

# 获取所需的.c文件
file(GLOB SRC_FILES "src/*.c")
list(APPEND SRC_FILES "src/cJSON/cJSON.c")

# 查找DPDK
if(ENABLE_DPDK)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(LIBDPDK REQUIRED libdpdk)

    if(NOT "${LIBDPDK_STATIC_LDFLAGS}" MATCHES ".*-Wl,--whole-archive.*-l:lib.*-Wl,--no-whole-archive.*")
        message(WARNING "pkg-config output does not contain drivers between 'whole-archive'/'no-whole-archive' flags")
        message(FATAL_ERROR "Cannot generate statically-linked binaries with this version of pkg-config")
    endif()

    add_compile_definitions(ENABLE_DPDK)

    file(GLOB DPDK_FILES "src/dpdk/*.c")
    list(APPEND SRC_FILES ${DPDK_FILES})
endif()

# 添加可执行目标
add_executable(cpworker ${SRC_FILES})

target_include_directories(cpworker PRIVATE
    ${LIBRARY_ROOT}/include
    ${CMAKE_CURRENT_BINARY_DIR}
    src
)

# 链接库（注意顺序）
target_link_libraries(cpworker
    ${LIBDPDK_STATIC_LDFLAGS}
    ${PCAP_LIB}
    ${ZMQ_LIB}
    pthread
    m

    # ZMQ require C++ runtime
    stdc++
)

if(ENABLE_UNIT_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

install(TARGETS cpworker RUNTIME DESTINATION bin COMPONENT cpworker)

if(NOT ENABLE_LINK_STATIC_LIBPCAP)
    get_filename_component(PCAP_REALPATH ${PCAP_LIB} REALPATH)
    get_filename_component(PCAP_FILENAME ${PCAP_REALPATH} NAME)

    install(FILES ${PCAP_REALPATH} DESTINATION lib COMPONENT cpworker)
    install(CODE "
        execute_process(
            COMMAND ${CMAKE_COMMAND} -E create_symlink
            \"${PCAP_FILENAME}\"
            \"libpcap.so.1\"
            WORKING_DIRECTORY \"\${CMAKE_INSTALL_PREFIX}/lib\"
        )
    " COMPONENT cpworker)
endif()
