cmake_minimum_required(VERSION 3.16)

project(linux_ipsec_library VERSION 0.1.0 LANGUAGES C)

option(IPSEC_BUILD_TESTS "Build host unit tests" ON)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(IPSEC_SOURCES
    core/buffer_validate.c
    core/context.c
    core/error.c
    core/ipsec.c
    core/log.c
    core/netlink.c
    core/psk.c
    core/secure_zero.c
    core/util.c
    ike/vici/vici_algorithm.c
    ike/vici/vici_client.c
    ike/vici/vici_connection.c
    ike/vici/vici_credential.c
    ike/vici/vici_packet.c
    ike/vici/vici_parser.c
    ike/vici/vici_sa.c
    ike/vici/vici_stats.c
    ike/vici/vici_transport.c
    datapath/common/datapath.c
    datapath/kernel_libipsec/kernel_libipsec_status.c
    datapath/xfrm/xfrm_policy.c
    datapath/xfrm/xfrm_state.c
    datapath/xfrm/xfrm_stats.c
    network/address.c
    network/interface.c
    network/route.c)

add_library(ipsec_objects OBJECT ${IPSEC_SOURCES})
set_target_properties(ipsec_objects PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_include_directories(ipsec_objects
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/internal
        ${CMAKE_CURRENT_SOURCE_DIR}/ike/vici
        ${CMAKE_CURRENT_SOURCE_DIR}/datapath/common
        ${CMAKE_CURRENT_SOURCE_DIR}/datapath/kernel_libipsec
        ${CMAKE_CURRENT_SOURCE_DIR}/datapath/xfrm
        ${CMAKE_CURRENT_SOURCE_DIR}/network)
target_compile_options(ipsec_objects PRIVATE -Wall -Wextra -Wpedantic -Werror)

add_library(ipsec_static STATIC $<TARGET_OBJECTS:ipsec_objects>)
add_library(ipsec_shared SHARED $<TARGET_OBJECTS:ipsec_objects>)
set_target_properties(ipsec_static PROPERTIES OUTPUT_NAME ipsec)
set_target_properties(ipsec_shared PROPERTIES OUTPUT_NAME ipsec)
target_include_directories(ipsec_static PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../include)
target_include_directories(ipsec_shared PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../include)
target_link_libraries(ipsec_static PUBLIC Threads::Threads)
target_link_libraries(ipsec_shared PUBLIC Threads::Threads)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_options(ipsec_shared PRIVATE
        "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/libipsec.map")
endif()

set_target_properties(ipsec_static ipsec_shared PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

if(IPSEC_BUILD_TESTS AND NOT CMAKE_CROSSCOMPILING)
    enable_testing()
    enable_language(CXX)

    foreach(TestName IN ITEMS
            test_vici_packet
            test_vici_stats
            test_xfrm_stats
            test_xfrm_netlink
            test_route_netlink
            test_psk_generate)
        add_executable(${TestName}
            ${CMAKE_CURRENT_SOURCE_DIR}/../tests/unit/${TestName}.c)
        target_include_directories(${TestName} PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/../include
            ${CMAKE_CURRENT_SOURCE_DIR}/internal
            ${CMAKE_CURRENT_SOURCE_DIR}/ike/vici
            ${CMAKE_CURRENT_SOURCE_DIR}/datapath/common
            ${CMAKE_CURRENT_SOURCE_DIR}/datapath/kernel_libipsec
            ${CMAKE_CURRENT_SOURCE_DIR}/datapath/xfrm
            ${CMAKE_CURRENT_SOURCE_DIR}/network)
        target_compile_definitions(${TestName} PRIVATE
            _POSIX_C_SOURCE=200809L)
        target_compile_options(${TestName} PRIVATE -Wall -Wextra -Wpedantic -Werror)
        target_link_libraries(${TestName} PRIVATE ipsec_static)
        add_test(NAME ${TestName} COMMAND ${TestName})
    endforeach()

    add_executable(test_cpp_header
        ${CMAKE_CURRENT_SOURCE_DIR}/../tests/unit/test_cpp_header.cpp)
    target_include_directories(test_cpp_header PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../include)
    target_compile_features(test_cpp_header PRIVATE cxx_std_11)
    target_compile_options(test_cpp_header PRIVATE -Wall -Wextra -Wpedantic -Werror)
    add_test(NAME test_cpp_header COMMAND test_cpp_header)
endif()
