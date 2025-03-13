cmake_minimum_required(VERSION 3.10)
project(cpagent C)

# 设置C标准
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# 库安装的根目录
set(LIBRARY_ROOT "/root/cpagent_libs_sdk")

# 添加头文件搜索路径
include_directories(${LIBRARY_ROOT}/include src contrib)

# 添加库搜索路径
link_directories(${LIBRARY_ROOT}/lib ${LIBRARY_ROOT}/lib64)

# 查找静态库
find_library(PCAP_LIB libpcap.a PATHS ${LIBRARY_ROOT}/lib NO_DEFAULT_PATH)
find_library(ZMQ_LIB libzmq.a PATHS ${LIBRARY_ROOT}/lib64 NO_DEFAULT_PATH)

# 检查库是否存在
if (NOT PCAP_LIB)
    message(FATAL_ERROR "libpcap.a not found in ${LIBRARY_ROOT}/lib")
endif()

if (NOT ZMQ_LIB)
    message(FATAL_ERROR "libzmq.a not found in ${LIBRARY_ROOT}/lib64")
endif()

# 查找DPDK
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBDPDK REQUIRED libdpdk)

# 获取src目录下所有.c文件
file(GLOB SRC_FILES "src/*.c")

# 添加 contrib 文件
list(APPEND SRC_FILES "contrib/cJSON/cJSON.c")

# 添加可执行目标
add_executable(cpagent ${SRC_FILES})

# 链接库（注意顺序）
target_link_libraries(cpagent
    ${LIBDPDK_STATIC_LDFLAGS}

    # 其他静态库
    ${PCAP_LIB}
    ${ZMQ_LIB}

    # ZMQ需要的C++运行时
    stdc++
)
