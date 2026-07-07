cmake_minimum_required(VERSION 4.1)
project(compact_tls C)

set(CMAKE_C_STANDARD 11)

# Role selection — exactly one must be ON.
# Client build (default): cmake -B build
# Server build:           cmake -B build -DCTLS_CLIENT=OFF -DCTLS_SERVER=ON
option(CTLS_CLIENT "Build as cTLS client" ON)
option(CTLS_SERVER "Build as cTLS server" OFF)

if(CTLS_CLIENT AND CTLS_SERVER)
    message(FATAL_ERROR "CTLS_CLIENT and CTLS_SERVER cannot both be ON")
endif()
if(NOT CTLS_CLIENT AND NOT CTLS_SERVER)
    message(FATAL_ERROR "One of CTLS_CLIENT or CTLS_SERVER must be ON")
endif()

# Transport selection — exactly one must be ON. Selects unified-header wire
# behavior (sequence number on/off the wire) and the HKDF label prefix.
# Default (unreliable): cmake -B build
# Reliable:              cmake -B build -DCTLS_TRANSPORT_UNRELIABLE=OFF -DCTLS_TRANSPORT_RELIABLE=ON
option(CTLS_TRANSPORT_RELIABLE "Reliable (TCP-like) transport framing" OFF)
option(CTLS_TRANSPORT_UNRELIABLE "Unreliable (UDP-like) transport framing" ON)

if(CTLS_TRANSPORT_RELIABLE AND CTLS_TRANSPORT_UNRELIABLE)
    message(FATAL_ERROR "CTLS_TRANSPORT_RELIABLE and CTLS_TRANSPORT_UNRELIABLE cannot both be ON")
endif()
if(NOT CTLS_TRANSPORT_RELIABLE AND NOT CTLS_TRANSPORT_UNRELIABLE)
    message(FATAL_ERROR "One of CTLS_TRANSPORT_RELIABLE or CTLS_TRANSPORT_UNRELIABLE must be ON")
endif()

list(APPEND CMAKE_PREFIX_PATH "/opt/homebrew")

find_package(MbedTLS REQUIRED)

include_directories(include)
include_directories(include/ctls)
include_directories(src)
include_directories(examples)

if(CTLS_CLIENT)
    set(CTLS_EXAMPLE_SRC examples/client.c)
else()
    set(CTLS_EXAMPLE_SRC examples/server.c)
endif()

add_executable(compact_tls
        ${CTLS_EXAMPLE_SRC}
        include/certs/ctls_certs.h
        include/ctls/bytes.h
        include/ctls/config.h
        include/ctls/core.h
        include/ctls/crypto.h
        include/ctls/ctls.h
        include/ctls/extensions.h
        include/ctls/hsmg.h
        include/ctls/record.h
        include/ctls/templates.h
        include/ctls/types.h
        src/core.c
        src/crypto.c
        src/ctls.c
        src/extensions.c
        src/hsmg.c
        src/record.c
        src/templates.c
)
target_compile_definitions(compact_tls PRIVATE
        CTLS_CLIENT=$<BOOL:${CTLS_CLIENT}>
        CTLS_SERVER=$<BOOL:${CTLS_SERVER}>
        CTLS_TRANSPORT_RELIABLE=$<BOOL:${CTLS_TRANSPORT_RELIABLE}>
        CTLS_TRANSPORT_UNRELIABLE=$<BOOL:${CTLS_TRANSPORT_UNRELIABLE}>
)
target_link_libraries(compact_tls
        MbedTLS::tfpsacrypto
)

