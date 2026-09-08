cmake_minimum_required(VERSION 3.16)

project(linux_ipsec_library VERSION 0.1.0 LANGUAGES C)

option(IPSEC_BUILD_TESTS "Build host unit tests" ON)
option(IPSEC_BUILD_APP "Build the interactive packet-path diagnostic application" ON)
option(IPSEC_BUILD_LIVE_TESTS "Build opt-in privileged datapath diagnostic (not a CTest)" OFF)

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
    ike/vici/vici_wait.c
    datapath/common/datapath.c
    datapath/common/datapath_health.c
    datapath/common/packet_path.c
    datapath/kernel_libipsec/kernel_libipsec_datapath.c
    datapath/kernel_libipsec/kernel_libipsec_status.c
    datapath/kernel_libipsec/kernel_libipsec_tun.c
    datapath/xfrm/xfrm_backend.c
    datapath/xfrm/xfrm_policy.c
    datapath/xfrm/xfrm_state.c
    datapath/xfrm/xfrm_stats.c
    datapath/protected/protected_path.c
    datapath/protected/system_protected_path.c
    datapath/protected/application_protected_path.c
    datapath/protected/application_protected_tun.c
    datapath/protected/application_protected_filter.c
    datapath/protected/application_protected_netlink.c
    datapath/protected/protected_packet.c
    datapath/plain/plain_path.c
    datapath/plain/system_plain_path.c
    datapath/plain/application_plain_path.c
    datapath/plain/plain_netfilter.c
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
        ${CMAKE_CURRENT_SOURCE_DIR}/datapath/protected
        ${CMAKE_CURRENT_SOURCE_DIR}/datapath/plain
        ${CMAKE_CURRENT_SOURCE_DIR}/datapath/xfrm
        ${CMAKE_CURRENT_SOURCE_DIR}/network)
target_compile_options(ipsec_objects PRIVATE -Wall -Wextra -Wpedantic -Werror)
target_link_libraries(ipsec_objects PRIVATE Threads::Threads)

add_library(ipsec_static STATIC $<TARGET_OBJECTS:ipsec_objects>)
add_library(ipsec_shared SHARED $<TARGET_OBJECTS:ipsec_objects>)
set_target_properties(ipsec_static PROPERTIES OUTPUT_NAME ipsecctrl)
set_target_properties(ipsec_shared PROPERTIES
    OUTPUT_NAME ipsecctrl VERSION ${PROJECT_VERSION} SOVERSION 0
    BUILD_WITH_INSTALL_RPATH TRUE)
target_include_directories(ipsec_static PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../include)
target_include_directories(ipsec_shared PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../include)
target_link_libraries(ipsec_static PUBLIC Threads::Threads)
target_link_libraries(ipsec_shared PUBLIC Threads::Threads)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_options(ipsec_shared PRIVATE
        "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/libipsecctrl.map")
endif()

set_target_properties(ipsec_static ipsec_shared PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

if(NOT DEFINED CMAKE_INSTALL_LIBDIR)
    set(CMAKE_INSTALL_LIBDIR "lib" CACHE PATH "Library installation directory")
endif()
include(GNUInstallDirs)
install(TARGETS ipsec_static ipsec_shared
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES ../include/ipsec.h ../include/ipsec_types.h ../include/ipsec_error.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/ipsecctrl)

if(IPSEC_BUILD_LIVE_TESTS)
    add_executable(test_live_tun_ingress ../tests/integration/test_live_tun_ingress.c)
    target_link_libraries(test_live_tun_ingress PRIVATE ipsec_static)
    target_compile_options(test_live_tun_ingress PRIVATE -Wall -Wextra -Wpedantic -Werror)
    add_executable(test_live_datapath ../tests/integration/test_live_datapath.c)
    target_compile_definitions(test_live_datapath PRIVATE _POSIX_C_SOURCE=200809L)
    target_link_libraries(test_live_datapath PRIVATE ipsec_static)
    target_compile_options(test_live_datapath PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()

if(IPSEC_BUILD_APP)
    add_executable(ipsec_app
        ../app/main.c ../app/cli.c ../app/command.c ../app/config.c
        ../app/datapath.c ../app/diagnostic_log.c ../app/packet.c ../app/lifecycle.c ../app/shutdown.c ../app/peer.c
        ../app/state.c ../app/show.c ../app/algorithm_capability.c
        ../app/algorithm_catalog.c ../app/algorithm_report.c ../app/algorithm_runner.c
        ../app/algorithm_packet.c ../app/algorithm_packet_codec.c
        ../app/algorithm_packet_evidence.c)
    target_compile_definitions(ipsec_app PRIVATE _POSIX_C_SOURCE=200809L)
    target_compile_options(ipsec_app PRIVATE -Wall -Wextra -Wpedantic -Werror)
    target_link_libraries(ipsec_app PRIVATE ipsec_static Threads::Threads ${CMAKE_DL_LIBS})
    set_target_properties(ipsec_app PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
endif()

if(IPSEC_BUILD_TESTS AND NOT CMAKE_CROSSCOMPILING)
    enable_testing()
    enable_language(CXX)

    foreach(TestName IN ITEMS
            test_vici_packet
            test_vici_stats
            test_vici_session
            test_xfrm_stats
            test_xfrm_netlink
            test_route_netlink
            test_tun_discovery
            test_protected_filter
            test_protected_tun
            test_plain_netfilter
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
            ${CMAKE_CURRENT_SOURCE_DIR}/datapath/protected
            ${CMAKE_CURRENT_SOURCE_DIR}/datapath/plain
            ${CMAKE_CURRENT_SOURCE_DIR}/network)
        target_compile_definitions(${TestName} PRIVATE
            _POSIX_C_SOURCE=200809L)
        target_compile_options(${TestName} PRIVATE -Wall -Wextra -Wpedantic -Werror)
        target_link_libraries(${TestName} PRIVATE ipsec_static)
        add_test(NAME ${TestName} COMMAND ${TestName})
        set_tests_properties(${TestName} PROPERTIES TIMEOUT 30)
    endforeach()

    # Compile the real managers/packet codec with deterministic OS/VICI seams.
    # No test-only hook or global mock is linked into the production library.
    add_executable(test_datapath_ops ../tests/unit/test_datapath_ops.c
        datapath/common/datapath.c datapath/common/datapath_health.c
        datapath/common/packet_path.c
        datapath/protected/protected_path.c
        datapath/protected/system_protected_path.c
        datapath/protected/application_protected_path.c
        datapath/protected/protected_packet.c
        datapath/plain/plain_path.c datapath/plain/system_plain_path.c
        datapath/plain/application_plain_path.c)
    target_include_directories(test_datapath_ops PRIVATE ../include)
    target_compile_definitions(test_datapath_ops PRIVATE _POSIX_C_SOURCE=200809L)
    target_compile_options(test_datapath_ops PRIVATE -Wall -Wextra -Wpedantic -Werror)
    target_link_libraries(test_datapath_ops PRIVATE Threads::Threads)
    add_test(NAME test_datapath_ops COMMAND test_datapath_ops)

    add_executable(test_shared_link ../tests/unit/test_shared_link.c)
    target_link_libraries(test_shared_link PRIVATE ipsec_shared)
    target_compile_options(test_shared_link PRIVATE -Wall -Wextra -Wpedantic -Werror)
    add_test(NAME test_shared_link COMMAND test_shared_link)

    # Compile only this test's packet object with an instrumented free; do not
    # add allocator hooks or a linker-specific --wrap dependency to production.
    add_library(test_sensitive_packet OBJECT ike/vici/vici_packet.c)
    target_include_directories(test_sensitive_packet PRIVATE ../include)
    target_compile_definitions(test_sensitive_packet PRIVATE free=TrackTestFree)
    target_compile_options(test_sensitive_packet PRIVATE -Wall -Wextra -Wpedantic -Werror)
    add_executable(test_sensitive_buffer ../tests/unit/test_sensitive_buffer.c
        $<TARGET_OBJECTS:test_sensitive_packet>)
    target_include_directories(test_sensitive_buffer PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/ike/vici)
    target_compile_options(test_sensitive_buffer PRIVATE -Wall -Wextra -Wpedantic -Werror)
    target_link_libraries(test_sensitive_buffer PRIVATE ipsec_static)
    add_test(NAME test_sensitive_buffer COMMAND test_sensitive_buffer)

    add_executable(test_algorithm_validation
        ${CMAKE_CURRENT_SOURCE_DIR}/../tests/unit/test_algorithm_validation.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../app/algorithm_catalog.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../app/algorithm_capability.c)
    target_include_directories(test_algorithm_validation PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../include
        ${CMAKE_CURRENT_SOURCE_DIR}/../app)
    target_compile_definitions(test_algorithm_validation PRIVATE
        _POSIX_C_SOURCE=200809L)
    target_compile_options(test_algorithm_validation PRIVATE
        -Wall -Wextra -Wpedantic -Werror)
    target_link_libraries(test_algorithm_validation PRIVATE
        ipsec_static ${CMAKE_DL_LIBS})
    add_test(NAME test_algorithm_validation COMMAND test_algorithm_validation)

    add_executable(test_app_state
        ${CMAKE_CURRENT_SOURCE_DIR}/../tests/unit/test_app_state.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../app/state.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../app/peer.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../app/command.c)
    target_include_directories(test_app_state PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../include
        ${CMAKE_CURRENT_SOURCE_DIR}/../app)
    target_compile_definitions(test_app_state PRIVATE
        _POSIX_C_SOURCE=200809L)
    target_compile_options(test_app_state PRIVATE
        -Wall -Wextra -Wpedantic -Werror)
    target_link_libraries(test_app_state PRIVATE
        ipsec_static Threads::Threads)
    add_test(NAME test_app_state COMMAND test_app_state)
    set_tests_properties(test_app_state PROPERTIES TIMEOUT 10)
    add_executable(test_app_shutdown ../tests/unit/test_app_shutdown.c
        ../app/shutdown.c ../app/state.c core/error.c)
    target_include_directories(test_app_shutdown PRIVATE ../include ../app)
    target_compile_definitions(test_app_shutdown PRIVATE _POSIX_C_SOURCE=200809L)
    target_compile_options(test_app_shutdown PRIVATE -Wall -Wextra -Wpedantic -Werror)
    add_test(NAME test_app_shutdown COMMAND test_app_shutdown)
    set_tests_properties(test_app_shutdown PROPERTIES TIMEOUT 10)

    # Keep the real wait routine with deterministic VICI seams; discard other
    # lifecycle entry points so production-only app dependencies are not mocked.
    add_executable(test_app_wait ../tests/unit/test_app_wait.c ../app/lifecycle.c)
    target_include_directories(test_app_wait PRIVATE ../include ../app)
    target_compile_definitions(test_app_wait PRIVATE _POSIX_C_SOURCE=200809L)
    target_compile_options(test_app_wait PRIVATE -Wall -Wextra -Wpedantic -Werror
        -ffunction-sections -fdata-sections)
    target_link_options(test_app_wait PRIVATE -Wl,--gc-sections)
    target_link_libraries(test_app_wait PRIVATE Threads::Threads)
    add_test(NAME test_app_wait COMMAND test_app_wait)
    set_tests_properties(test_app_wait PROPERTIES TIMEOUT 10)

    add_executable(test_app_command
        ${CMAKE_CURRENT_SOURCE_DIR}/../tests/unit/test_app_command.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../app/command.c)
    target_include_directories(test_app_command PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../include
        ${CMAKE_CURRENT_SOURCE_DIR}/../app)
    target_compile_definitions(test_app_command PRIVATE
        _POSIX_C_SOURCE=200809L)
    target_compile_options(test_app_command PRIVATE
        -Wall -Wextra -Wpedantic -Werror)
    add_test(NAME test_app_command COMMAND test_app_command)

    add_executable(test_app_datapath ../tests/unit/test_app_datapath.c
        ../app/config.c ../app/datapath.c ../app/command.c)
    add_executable(test_app_packet ../tests/unit/test_app_packet.c ../app/packet.c)
    add_executable(test_algorithm_packet_codec ../tests/unit/test_algorithm_packet_codec.c
        ../app/algorithm_packet_codec.c)
    target_include_directories(test_algorithm_packet_codec PRIVATE ../include ../app)
    target_compile_options(test_algorithm_packet_codec PRIVATE -Wall -Wextra -Wpedantic -Werror)
    add_test(NAME test_algorithm_packet_codec COMMAND test_algorithm_packet_codec)
    add_executable(test_algorithm_packet_evidence ../tests/unit/test_algorithm_packet_evidence.c
        ../app/algorithm_packet_codec.c ../app/algorithm_packet_evidence.c)
    target_include_directories(test_algorithm_packet_evidence PRIVATE ../include ../app)
    target_compile_definitions(test_algorithm_packet_evidence PRIVATE _POSIX_C_SOURCE=200809L)
    target_compile_options(test_algorithm_packet_evidence PRIVATE -Wall -Wextra -Wpedantic -Werror)
    target_link_libraries(test_algorithm_packet_evidence PRIVATE ipsec_static)
    add_test(NAME test_algorithm_packet_evidence COMMAND test_algorithm_packet_evidence)
    add_executable(test_algorithm_packet_transport ../tests/unit/test_algorithm_packet_transport.c
        ../app/algorithm_packet.c ../app/algorithm_packet_codec.c ../app/algorithm_packet_evidence.c
        ../app/diagnostic_log.c)
    target_include_directories(test_algorithm_packet_transport PRIVATE ../include ../app)
    target_compile_definitions(test_algorithm_packet_transport PRIVATE _POSIX_C_SOURCE=200809L)
    target_compile_options(test_algorithm_packet_transport PRIVATE -Wall -Wextra -Wpedantic -Werror)
    target_link_libraries(test_algorithm_packet_transport PRIVATE ipsec_static Threads::Threads)
    add_test(NAME test_algorithm_packet_transport COMMAND test_algorithm_packet_transport)
    set_tests_properties(test_algorithm_packet_transport PROPERTIES TIMEOUT 10)
    add_executable(test_app_diagnostic_log ../tests/unit/test_app_diagnostic_log.c
        ../app/diagnostic_log.c)
    target_include_directories(test_app_diagnostic_log PRIVATE ../include ../app)
    target_compile_definitions(test_app_diagnostic_log PRIVATE _POSIX_C_SOURCE=200809L)
    target_compile_options(test_app_diagnostic_log PRIVATE -Wall -Wextra -Wpedantic -Werror)
    target_link_libraries(test_app_diagnostic_log PRIVATE Threads::Threads)
    add_test(NAME test_app_diagnostic_log COMMAND test_app_diagnostic_log)
    foreach(TestName IN ITEMS test_app_datapath test_app_packet)
        target_include_directories(${TestName} PRIVATE ../include ../app)
        target_compile_definitions(${TestName} PRIVATE _POSIX_C_SOURCE=200809L)
        target_compile_options(${TestName} PRIVATE -Wall -Wextra -Wpedantic -Werror)
        target_link_libraries(${TestName} PRIVATE Threads::Threads)
        add_test(NAME ${TestName} COMMAND ${TestName})
        set_tests_properties(${TestName} PROPERTIES TIMEOUT 10)
    endforeach()
    if(IPSEC_BUILD_APP)
        add_test(NAME test_app_help COMMAND ipsec_app --help)
        set_tests_properties(test_app_help PROPERTIES TIMEOUT 10)
    endif()

    add_executable(test_cpp_header
        ${CMAKE_CURRENT_SOURCE_DIR}/../tests/unit/test_cpp_header.cpp)
    target_include_directories(test_cpp_header PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../include)
    target_compile_features(test_cpp_header PRIVATE cxx_std_11)
    target_compile_options(test_cpp_header PRIVATE -Wall -Wextra -Wpedantic -Werror)
    add_test(NAME test_cpp_header COMMAND test_cpp_header)
endif()
