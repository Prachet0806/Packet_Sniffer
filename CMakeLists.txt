cmake_minimum_required(VERSION 3.16)
project(packet_sniffer C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Sources (explicit list so missing files fail fast)
set(SNIFFER_SOURCES
    src/main.c
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
)

add_executable(sniffer ${SNIFFER_SOURCES})

target_include_directories(sniffer PRIVATE src)

if(MSVC)
    target_compile_options(sniffer PRIVATE /W4)
else()
    target_compile_options(sniffer PRIVATE -Wall -Wextra -Wpedantic)
endif()

# Allow overriding SDK locations via env vars:
#   NPCAP_SDK, POSTGRES_ROOT
if(WIN32)
    if(DEFINED ENV{NPCAP_SDK})
        target_include_directories(sniffer PRIVATE $ENV{NPCAP_SDK}/Include)
        target_link_directories(sniffer PRIVATE $ENV{NPCAP_SDK}/Lib/x64)
    elseif(EXISTS "C:/npcap-sdk/Include")
        target_include_directories(sniffer PRIVATE C:/npcap-sdk/Include)
        target_link_directories(sniffer PRIVATE C:/npcap-sdk/Lib/x64)
    endif()
    if(DEFINED ENV{POSTGRES_ROOT})
        target_include_directories(sniffer PRIVATE $ENV{POSTGRES_ROOT}/include)
        target_link_directories(sniffer PRIVATE $ENV{POSTGRES_ROOT}/lib)
    endif()
    target_link_libraries(sniffer PRIVATE wpcap Packet ws2_32 iphlpapi)
    # libpq is optional: build still works without PostgreSQL
    find_library(LIBPQ_LIB pq libpq PATHS
        "$ENV{POSTGRES_ROOT}/lib"
        "C:/Program Files/PostgreSQL/17/lib"
        "C:/Program Files/PostgreSQL/16/lib")
    find_path(LIBPQ_INCLUDE_DIR libpq-fe.h PATHS
        "$ENV{POSTGRES_ROOT}/include"
        "C:/Program Files/PostgreSQL/17/include"
        "C:/Program Files/PostgreSQL/16/include")
    if(LIBPQ_LIB AND LIBPQ_INCLUDE_DIR)
        target_include_directories(sniffer PRIVATE ${LIBPQ_INCLUDE_DIR})
        target_link_libraries(sniffer PRIVATE ${LIBPQ_LIB})
        target_compile_definitions(sniffer PRIVATE HAVE_LIBPQ=1)
    else()
        message(WARNING "libpq not found; PostgreSQL support disabled. Set POSTGRES_ROOT.")
    endif()
else()
    find_path(PCAP_INCLUDE_DIR pcap.h)
    find_library(PCAP_LIB pcap)
    if(NOT PCAP_LIB)
        message(FATAL_ERROR "libpcap not found. Install libpcap-dev (apt) / libpcap-devel (yum).")
    endif()
    target_include_directories(sniffer PRIVATE ${PCAP_INCLUDE_DIR})
    target_link_libraries(sniffer PRIVATE ${PCAP_LIB} pthread)
    find_path(LIBPQ_INCLUDE_DIR libpq-fe.h PATHS /usr/include/postgresql)
    find_library(LIBPQ_LIB pq)
    if(LIBPQ_LIB)
        if(LIBPQ_INCLUDE_DIR)
            target_include_directories(sniffer PRIVATE ${LIBPQ_INCLUDE_DIR})
        endif()
        target_link_libraries(sniffer PRIVATE ${LIBPQ_LIB})
        target_compile_definitions(sniffer PRIVATE HAVE_LIBPQ=1)
    else()
        message(WARNING "libpq not found; PostgreSQL support disabled.")
    endif()
endif()

# Pthreads on Windows via MSVC is built-in via CriticalSection abstraction;
# no extra link needed there.
