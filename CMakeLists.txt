cmake_minimum_required(VERSION 2.8)
project(pktminerg)

option(PROJECT_WITH_PROF "Enable profiling and coverage report analysis" OFF)

message("\${PROJECT_WITH_PROF}: ${PROJECT_WITH_PROF}")
# cmake cxx flags
if (${PROJECT_WITH_PROF})
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall -fprofile-arcs -ftest-coverage")
    set(LINK_FLAGS "${LINK_FLAGS} -fprofile-arcs")
else ()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall")
endif ()

# set PKTMINERG_MAJOR_VERSION, PKTMINERG_MINOR_VERSION, etc.
set(PKTMINERG_MAJOR_VERSION "0")
set(PKTMINERG_MINOR_VERSION "3")
set(PKTMINERG_PATCH_VERSION "1")
set(PKTMINERG_VERSION_STRING "${PKTMINERG_MAJOR_VERSION}.${PKTMINERG_MINOR_VERSION}.${PKTMINERG_PATCH_VERSION}")

# Get the current working branch
execute_process(
        COMMAND git rev-parse --abbrev-ref HEAD
        #    COMMAND git symbolic-ref --short HEAD
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        OUTPUT_VARIABLE GIT_BRANCH
        OUTPUT_STRIP_TRAILING_WHITESPACE
)

message("branch: " ${GIT_BRANCH})

# Get the latest abbreviated commit hash of the working branch
execute_process(
        COMMAND git log -1 --format=%h
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        OUTPUT_VARIABLE GIT_COMMIT_HASH
        OUTPUT_STRIP_TRAILING_WHITESPACE
)

message("commit: " ${GIT_COMMIT_HASH})

# Get build time
string(TIMESTAMP BUILD_TIME "%Y-%m-%d %H:%M:%S")

add_definitions("-DGIT_COMMIT_HASH=${GIT_COMMIT_HASH}")
add_definitions("-DGIT_BRANCH=${GIT_BRANCH}")
add_definitions("-DBUILD_TIME=${BUILD_TIME}")

configure_file(
        ${PROJECT_SOURCE_DIR}/version.h.in
        ${PROJECT_BINARY_DIR}/version.h
)

if(APPLE)
    find_library(LIBPCAP NAMES libpcap.dylib)
    find_library(LIBSTDCPP NAMES libstdc++.6.dylib)
    find_library(LIBGCCS NAMES libgcc_s.1.dylib)
    add_definitions(-DMAC)
elseif(UNIX)
    find_library(LIBPCAP NAMES libpcap.so)
    find_library(LIBSTDCPP NAMES libstdc++.so.6)
    find_library(LIBGCCS NAMES libgcc_s.so.1)
endif()


if (NOT LIBPCAP)
    message(FATAL_ERROR "lib pcap not found")
endif()
message("LIBPCAP: " ${LIBPCAP})


if (NOT LIBSTDCPP)
    message(FATAL_ERROR "lib stdcpp not found")
endif()
message("LIBSTDCPP: " ${LIBSTDCPP})


if (NOT LIBGCCS)
    message(FATAL_ERROR "lib gccs not found")
endif()
message("LIBGCCS: " ${LIBGCCS})


INCLUDE(FindBoost)
set(Boost_USE_STATIC_LIBS ON)
find_package(Boost 1.41.0 REQUIRED COMPONENTS program_options system filesystem)

message("Boost_INCLUDE_DIRS: " ${Boost_INCLUDE_DIRS})
message("Boost_LIBRARY_DIRS: " ${Boost_LIBRARY_DIRS})
# include dir
include_directories(
        ${PROJECT_SOURCE_DIR}/include
        ${PROJECT_BINARY_DIR}
        ${Boost_INCLUDE_DIRS}
)

if(UNIX AND NOT APPLE)
    # link dir
link_directories(${Boost_LIBRARY_DIRS})

# read the real file which libpcap.so links to
    execute_process(COMMAND readlink -f ${LIBPCAP}
            OUTPUT_VARIABLE PCAP_REAL_FILE OUTPUT_STRIP_TRAILING_WHITESPACE)
    message("PCAP REAL FILE: " ${PCAP_REAL_FILE})

    # read the real file which libstdc++.so links to
    execute_process(COMMAND readlink -f ${LIBSTDCPP}
            OUTPUT_VARIABLE STDCPP_REAL_FILE OUTPUT_STRIP_TRAILING_WHITESPACE)
    message("STDCPP REAL FILE: " ${STDCPP_REAL_FILE})

    # read the real file which libgcc_s.so links to
    execute_process(COMMAND readlink -f ${LIBGCCS}
            OUTPUT_VARIABLE GCCS_REAL_FILE OUTPUT_STRIP_TRAILING_WHITESPACE)
    message("GCCS REAL FILE: " ${GCCS_REAL_FILE})

    # read the real file which libboost_*.so links to
    execute_process(COMMAND readlink -f ${Boost_FILESYSTEM_LIBRARY}
            OUTPUT_VARIABLE BOOST_FILESYSTEM_REAL_FILE OUTPUT_STRIP_TRAILING_WHITESPACE)
    execute_process(COMMAND readlink -f ${Boost_PROGRAM_OPTIONS_LIBRARY}
            OUTPUT_VARIABLE BOOST_PROGRAM_OPTIONS_REAL_FILE OUTPUT_STRIP_TRAILING_WHITESPACE)
    execute_process(COMMAND readlink -f ${Boost_SYSTEM_LIBRARY}
            OUTPUT_VARIABLE BOOST_SYSTEM_REAL_FILE OUTPUT_STRIP_TRAILING_WHITESPACE)


    # mkdir tmp dir to store third party lib
    file(MAKE_DIRECTORY ${PROJECT_BINARY_DIR}/netis)
    file(MAKE_DIRECTORY ${PROJECT_BINARY_DIR}/3rdlib)

    file(COPY
            ${BOOST_FILESYSTEM_REAL_FILE}
            ${BOOST_PROGRAM_OPTIONS_REAL_FILE}
            ${BOOST_SYSTEM_REAL_FILE}
            ${PCAP_REAL_FILE}
            ${STDCPP_REAL_FILE}
            ${GCCS_REAL_FILE}
            DESTINATION ${PROJECT_BINARY_DIR}/3rdlib
            )

    # make link file
    execute_process(COMMAND basename ${LIBPCAP} OUTPUT_VARIABLE BN_PCAP_LINK OUTPUT_STRIP_TRAILING_WHITESPACE)
    execute_process(COMMAND basename ${PCAP_REAL_FILE} OUTPUT_VARIABLE BN_PCAP_REAL OUTPUT_STRIP_TRAILING_WHITESPACE)
    execute_process(COMMAND ln -s ${BN_PCAP_REAL} ${BN_PCAP_LINK} WORKING_DIRECTORY ${PROJECT_BINARY_DIR}/3rdlib)

    execute_process(COMMAND basename ${LIBSTDCPP} OUTPUT_VARIABLE BN_STDCPP_LINK OUTPUT_STRIP_TRAILING_WHITESPACE)
    execute_process(COMMAND basename ${STDCPP_REAL_FILE} OUTPUT_VARIABLE BN_STDCPP_REAL OUTPUT_STRIP_TRAILING_WHITESPACE)
    execute_process(COMMAND ln -s ${BN_STDCPP_REAL} ${BN_STDCPP_LINK} WORKING_DIRECTORY ${PROJECT_BINARY_DIR}/3rdlib)

    execute_process(COMMAND basename ${LIBGCCS} OUTPUT_VARIABLE BN_GCCS_LINK OUTPUT_STRIP_TRAILING_WHITESPACE)
    execute_process(COMMAND basename ${GCCS_REAL_FILE} OUTPUT_VARIABLE BN_GCCS_REAL OUTPUT_STRIP_TRAILING_WHITESPACE)
    execute_process(COMMAND ln -s ${BN_GCCS_REAL} ${BN_GCCS_LINK} WORKING_DIRECTORY ${PROJECT_BINARY_DIR}/3rdlib)
endif()
# link dir
option(PLATFORM_DEBIAN "Build on Linux Platform Debian" OFF)
if (${PLATFORM_DEBIAN})
    message("\${PLATFORM_DEBIAN}: ${PLATFORM_DEBIAN}")
    link_directories(${PROJECT_SOURCE_DIR}/debian_lib)
else ()
    link_directories(${PROJECT_SOURCE_DIR}/lib)
endif ()


# output dir
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/bin)

# source
set(SOURCE_FILES_GREDEMO
        ${PROJECT_SOURCE_DIR}/tools/gredemo.cpp
        )

set(SOURCE_FILES_GREDUMP
        ${PROJECT_SOURCE_DIR}/tools/gredump.cpp
        )

set(SOURCE_FILES_PCAPCOMPARE
        ${PROJECT_SOURCE_DIR}/tools/pcapcompare.cpp
        )

set(SOURCE_FILES_PKTMINERG_BASE
        ${PROJECT_SOURCE_DIR}/src/syshelp.cpp
        ${PROJECT_SOURCE_DIR}/src/socketgre.cpp
        ${PROJECT_SOURCE_DIR}/src/pcaphandler.cpp
        ${PROJECT_SOURCE_DIR}/src/statislog.cpp
        )

set(SOURCE_FILES_PKTMINERG
        ${SOURCE_FILES_PKTMINERG_BASE}
        ${PROJECT_SOURCE_DIR}/src/pktminerg.cpp
        )


# about install
set(CMAKE_INSTALL_PREFIX ${PROJECT_BINARY_DIR}/netis)
set(CMAKE_SKIP_BUILD_RPATH FALSE)
set(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)
set(CMAKE_INSTALL_RPATH "/opt/netis/lib")
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH FALSE)

set(BOOST_LIB boost_program_options.a boost_system.a boost_filesystem.a)

# bin -- gredemo
add_executable(gredemo ${SOURCE_FILES_GREDEMO})
target_link_libraries(gredemo ${BOOST_LIB})

# bin -- gredump
add_executable(gredump ${SOURCE_FILES_GREDUMP})
target_link_libraries(gredump ${BOOST_LIB} pcap)

# bin -- pcapcompare
add_executable(pcapcompare ${SOURCE_FILES_PCAPCOMPARE})
target_link_libraries(pcapcompare ${BOOST_LIB} pcap)

# bin -- pktminerg
add_executable(pktminerg ${SOURCE_FILES_PKTMINERG})
target_link_libraries(pktminerg ${BOOST_LIB} pcap)

if(UNIX AND NOT APPLE)
    # test
    set(TEST_DIR ${PROJECT_SOURCE_DIR}/test)
    set(GTEST_LIB gtest gtest_main)

    # unit test
    set(SOURCE_FILES_UNITTEST ${TEST_DIR}/unit_test.cpp)
    add_executable(unittest ${SOURCE_FILES_UNITTEST} ${SOURCE_FILES_PKTMINERG_BASE})
    target_link_libraries(unittest ${GTEST_LIB} ${BOOST_LIB} pcap pthread)
    set_target_properties(unittest PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PROJECT_SOURCE_DIR}/test/bin")
endif()

install(FILES
        DESTINATION lib COMPONENT pktminerg)

install(TARGETS pktminerg gredump pcapcompare DESTINATION bin COMPONENT pktminerg)

# cpack
set(CPACK_RPM_COMPONENT_INSTALL ON)
set(CPACK_PACKAGE_NAME "netis-packet-agent")
set(CPACK_PACKAGE_VENDOR "netis")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Netis packet agent tools")
set(CPACK_PACKAGE_VERSION ${PKTMINERG_VERSION_STRING})
set(CPACK_GENERATOR "RPM")
set(CPACK_PACKAGING_INSTALL_PREFIX "/usr/local")
set(CPACK_OUTPUT_FILE_PREFIX ${CMAKE_CURRENT_SOURCE_DIR}/installer)
set(CPACK_PACKAGE_FILE_NAME ${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}.el6.${CMAKE_SYSTEM_PROCESSOR})
#set(CPACK_COMPONENTS_ALL pktminerg)
include(CPack)
