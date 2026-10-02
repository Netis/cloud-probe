# add_subdirectory(unity)
add_library(unity STATIC unity/src/unity.c)

# 获取主项目源文件（排除main.c）
file(GLOB MAIN_SRCS
    "${cpworker_SOURCE_DIR}/src/*.c"
    "${cpworker_SOURCE_DIR}/src/cJSON/cJSON.c"
)
set(NORMALIZED_MAIN_SRCS)
foreach(src ${MAIN_SRCS})
    get_filename_component(abs_src "${src}" REALPATH)
    list(APPEND NORMALIZED_MAIN_SRCS "${abs_src}")
endforeach()
set(MAIN_SRCS "${NORMALIZED_MAIN_SRCS}")

# 确保移除包含main函数的文件
get_filename_component(MAIN_C_ABS_PATH "${cpworker_SOURCE_DIR}/src/main.c" ABSOLUTE)
list(REMOVE_ITEM MAIN_SRCS "${MAIN_C_ABS_PATH}")

if(ENABLE_DPDK)
    file(GLOB DPDK_FILES "${cpworker_SOURCE_DIR}/src/dpdk/*.c")
    list(APPEND MAIN_SRCS ${DPDK_FILES})
endif()

set(MAIN_CONFIG_DIR "${CMAKE_BINARY_DIR}")

set(unity_tests
    config_validation
    misc
    output_file
    output_rotating_file
    output_zmq
    packet_split
    req_pattern
    unix_control
)

# fault_paths relies on GNU ld's --wrap to inject allocation, setns and thread-start faults.
if(OS_LINUX)
    list(APPEND unity_tests fault_paths)
endif()

foreach(unity_test ${unity_tests})
    add_executable("${unity_test}"
        "${unity_test}.c"
        ${MAIN_SRCS}
    )

    target_include_directories("${unity_test}" PRIVATE
        "${cpworker_SOURCE_DIR}/src"
        "${MAIN_CONFIG_DIR}"
        ${LIBRARY_ROOT}/include
    )

    # 传递主项目的编译定义（如ENABLE_DPDK）
    target_compile_definitions("${unity_test}" PRIVATE
        $<$<BOOL:${ENABLE_DPDK}>:ENABLE_DPDK>
    )

    target_compile_options("${unity_test}" PRIVATE ${CPWORKER_WARNING_OPTIONS})

    target_link_libraries("${unity_test}"
        unity
        ${LIBDPDK_STATIC_LDFLAGS}
        ${PCAP_LIB}
        ${ZMQ_LIB}
        pthread
        m
        stdc++
    )

    add_test(
        NAME "${unity_test}"
        COMMAND "./${unity_test}"
    )
endforeach()

if(OS_LINUX)
    target_sources(fault_paths PRIVATE fault_hooks.c)
    target_link_libraries(fault_paths
        "-Wl,--wrap=malloc,--wrap=calloc,--wrap=realloc,--wrap=free,--wrap=strdup,--wrap=__strdup"
        "-Wl,--wrap=setns,--wrap=pthread_create"
    )
endif()
