cmake_minimum_required(VERSION 3.16)
project(packet_sniffer C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Sources (explicit list so missing files fail fast)
set(SNIFFER_LIB_SOURCES
    src/sniffer.c
    src/analyzer.c
    src/ethernet.c
    src/ip.c
    src/arp.c
    src/dns.c
    src/icmp.c
    src/tcp.c
    src/udp.c
    src/http.c
    src/https.c
    src/dhcp.c
    src/logger.c
    src/stats.c
    src/db.c
    src/security.c
    src/api.c
)

add_library(sniffer_lib STATIC ${SNIFFER_LIB_SOURCES})
target_include_directories(sniffer_lib PUBLIC src)

add_executable(sniffer src/main.c)
target_include_directories(sniffer PRIVATE src)
target_link_libraries(sniffer PRIVATE sniffer_lib)

if(MSVC)
    target_compile_options(sniffer_lib PRIVATE /W4 /std:c11)
    target_compile_options(sniffer PRIVATE /W4 /std:c11)
else()
    target_compile_options(sniffer_lib PRIVATE -Wall -Wextra -Wpedantic -std=c11)
    target_compile_options(sniffer PRIVATE -Wall -Wextra -Wpedantic -std=c11)
endif()
if(WIN32)
    target_compile_definitions(sniffer_lib PUBLIC WIN32_LEAN_AND_MEAN _WINSOCK_DEPRECATED_NO_WARNINGS _CRT_SECURE_NO_WARNINGS)
endif()

# Allow overriding SDK locations via env vars:
#   NPCAP_SDK, POSTGRES_ROOT
if(WIN32)
    # Determine architecture-specific lib directory
    set(NPCAP_LIB_ARCH "x64")
    if(CMAKE_SYSTEM_PROCESSOR STREQUAL "ARM64" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "AARCH64")
        set(NPCAP_LIB_ARCH "arm64")
    endif()
    
    if(DEFINED ENV{NPCAP_SDK})
        target_include_directories(sniffer_lib PUBLIC $ENV{NPCAP_SDK}/Include)
        target_link_directories(sniffer_lib PUBLIC $ENV{NPCAP_SDK}/Lib/${NPCAP_LIB_ARCH})
        # Stage Npcap runtime DLLs next to the test executables. The SDK lib
        # dir ships only .lib files; CopyNpcapDLLs.cmake falls back to the
        # installed runtime locations (C:/Windows/System32/Npcap, ...).
        add_custom_command(TARGET sniffer POST_BUILD
            COMMAND ${CMAKE_COMMAND}
                "-DNPCAP_SRC_DIR=$ENV{NPCAP_SDK}/Lib/${NPCAP_LIB_ARCH}"
                "-DNPCAP_DST_DIR=$<TARGET_FILE_DIR:sniffer>"
                -P "${CMAKE_SOURCE_DIR}/cmake/CopyNpcapDLLs.cmake"
            COMMENT "Copying Npcap DLLs for test execution"
        )
    elseif(EXISTS "C:/npcap-sdk/Include")
        target_include_directories(sniffer_lib PUBLIC C:/npcap-sdk/Include)
        target_link_directories(sniffer_lib PUBLIC C:/npcap-sdk/Lib/${NPCAP_LIB_ARCH})
        add_custom_command(TARGET sniffer POST_BUILD
            COMMAND ${CMAKE_COMMAND}
                "-DNPCAP_SRC_DIR=C:/npcap-sdk/Lib/${NPCAP_LIB_ARCH}"
                "-DNPCAP_DST_DIR=$<TARGET_FILE_DIR:sniffer>"
                -P "${CMAKE_SOURCE_DIR}/cmake/CopyNpcapDLLs.cmake"
            COMMENT "Copying Npcap DLLs for test execution"
        )
    elseif(EXISTS "C:/Program Files/Npcap-sdk/Include")
        target_include_directories(sniffer_lib PUBLIC "C:/Program Files/Npcap-sdk/Include")
        target_link_directories(sniffer_lib PUBLIC "C:/Program Files/Npcap-sdk/Lib/${NPCAP_LIB_ARCH}")
        add_custom_command(TARGET sniffer POST_BUILD
            COMMAND ${CMAKE_COMMAND}
                "-DNPCAP_SRC_DIR=C:/Program Files/Npcap-sdk/Lib/${NPCAP_LIB_ARCH}"
                "-DNPCAP_DST_DIR=$<TARGET_FILE_DIR:sniffer>"
                -P "${CMAKE_SOURCE_DIR}/cmake/CopyNpcapDLLs.cmake"
            COMMENT "Copying Npcap DLLs for test execution"
        )
    endif()
    if(DEFINED ENV{POSTGRES_ROOT})
        target_include_directories(sniffer_lib PUBLIC $ENV{POSTGRES_ROOT}/include)
        target_link_directories(sniffer_lib PUBLIC $ENV{POSTGRES_ROOT}/lib)
    endif()
    target_link_libraries(sniffer_lib PUBLIC wpcap Packet ws2_32 iphlpapi)
    # libpq is optional: build still works without PostgreSQL
    find_library(LIBPQ_LIB pq libpq PATHS
        "$ENV{POSTGRES_ROOT}/lib"
        "C:/Program Files/PostgreSQL/17/lib"
        "C:/Program Files/PostgreSQL/16/lib"
        "C:/Program Files/PostgreSQL/15/lib"
        "C:/Program Files/PostgreSQL/14/lib")
    find_path(LIBPQ_INCLUDE_DIR libpq-fe.h PATHS
        "$ENV{POSTGRES_ROOT}/include"
        "C:/Program Files/PostgreSQL/17/include"
        "C:/Program Files/PostgreSQL/16/include"
        "C:/Program Files/PostgreSQL/15/include"
        "C:/Program Files/PostgreSQL/14/include")
    if(LIBPQ_LIB AND LIBPQ_INCLUDE_DIR)
        target_include_directories(sniffer_lib PUBLIC ${LIBPQ_INCLUDE_DIR})
        target_link_libraries(sniffer_lib PUBLIC ${LIBPQ_LIB})
        target_compile_definitions(sniffer_lib PUBLIC HAVE_LIBPQ=1)
    else()
        message(WARNING "libpq not found; PostgreSQL support disabled. Set POSTGRES_ROOT.")
    endif()
else()
    # glibc with -std=c11 hides BSD types (u_char/u_short/u_int) used by
    # libpcap unless _DEFAULT_SOURCE is defined, and hides clock_gettime/
    # nanosleep unless _POSIX_C_SOURCE>=199309L. Define on the command line
    # so it applies before ANY system header in every TU (per-file #defines
    # are too late once pcap.h is pulled in transitively).
    target_compile_definitions(sniffer_lib PUBLIC _DEFAULT_SOURCE _POSIX_C_SOURCE=200809L)
    find_path(PCAP_INCLUDE_DIR pcap.h)
    find_library(PCAP_LIB pcap)
    if(NOT PCAP_LIB)
        message(FATAL_ERROR "libpcap not found. Install libpcap-dev (apt) / libpcap-devel (yum).")
    endif()
    target_include_directories(sniffer_lib PUBLIC ${PCAP_INCLUDE_DIR})
    target_link_libraries(sniffer_lib PUBLIC ${PCAP_LIB} pthread)
    find_path(LIBPQ_INCLUDE_DIR libpq-fe.h PATHS /usr/include/postgresql)
    find_library(LIBPQ_LIB pq)
    if(LIBPQ_LIB)
        if(LIBPQ_INCLUDE_DIR)
            target_include_directories(sniffer_lib PUBLIC ${LIBPQ_INCLUDE_DIR})
        endif()
        target_link_libraries(sniffer_lib PUBLIC ${LIBPQ_LIB})
        target_compile_definitions(sniffer_lib PUBLIC HAVE_LIBPQ=1)
    else()
        message(WARNING "libpq not found; PostgreSQL support disabled.")
    endif()
endif()

# Pthreads on Windows via MSVC is built-in via CriticalSection abstraction;
# no extra link needed there.

enable_testing()
add_executable(smoke tests/smoke_parsers.c)
target_link_libraries(smoke PRIVATE sniffer_lib)
if(NOT MSVC)
    target_link_libraries(smoke PRIVATE pthread)
endif()
add_test(NAME smoke COMMAND smoke "${CMAKE_BINARY_DIR}/smoke-stats.json")
add_test(NAME help COMMAND sniffer --help)
set_tests_properties(smoke help PROPERTIES WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
# Long-lived API fixture for manual curl checks (not run by default in ctest)
add_executable(api_alive tests/api_alive.c)
target_link_libraries(api_alive PRIVATE sniffer_lib)
if(EXISTS "${CMAKE_SOURCE_DIR}/tests/pcaps/eth-tcp-http.pcap")
    add_test(NAME replay
        COMMAND sniffer --read "${CMAKE_SOURCE_DIR}/tests/pcaps/eth-tcp-http.pcap" --no-db --quiet)
    set_tests_properties(replay PROPERTIES WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
endif()
