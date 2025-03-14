cmake_minimum_required(VERSION 3.10)
project(recvzmq C)

# 设置C标准
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(LIBRARY_ROOT "/root/cpagent_libs_sdk")

# 添加库搜索路径
link_directories(${LIBRARY_ROOT}/lib ${LIBRARY_ROOT}/lib64)

# 查找静态库
find_library(ZMQ_LIB libzmq.a PATHS ${LIBRARY_ROOT}/lib64 NO_DEFAULT_PATH)

# 检查库是否存在
if (NOT ZMQ_LIB)
    message(FATAL_ERROR "libzmq.a not found in ${LIBRARY_ROOT}/lib64")
endif()

# 添加可执行目标
add_executable(recvzmq main.c)

target_link_libraries(recvzmq
    ${ZMQ_LIB}
    pthread
    stdc++
)
