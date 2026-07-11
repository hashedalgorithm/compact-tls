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
# Reliable:              cmake -B build -DCTLS_DATAGRAM=OFF -DCTLS_STREAM=ON
option(CTLS_STREAM "Reliable (TCP-like) transport framing" OFF)
option(CTLS_DATAGRAM "Unreliable (UDP-like) transport framing" ON)

if(CTLS_STREAM AND CTLS_DATAGRAM)
    message(FATAL_ERROR "CTLS_STREAM and CTLS_DATAGRAM cannot both be ON")
endif()
if(NOT CTLS_STREAM AND NOT CTLS_DATAGRAM)
    message(FATAL_ERROR "One of CTLS_STREAM or CTLS_DATAGRAM must be ON")
endif()

# Mbed TLS 4.x split PSA Crypto into its own submodule (tf-psa-crypto) and
# only got a stable release in 2025 — too new for any distro's package
# manager (Ubuntu/WSL apt only ships 2.x/3.x, with no tfpsacrypto target and
# no PSA Crypto API at this level). Rather than requiring a matching
# system-wide install, fetch and build the exact pinned version from source
# here: identical binary on macOS/Linux/WSL/Windows, no find_package
# guessing games, no host package manager required at all.
include(FetchContent)

set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(USE_SHARED_MBEDTLS_LIBRARY OFF CACHE BOOL "" FORCE)
set(USE_STATIC_MBEDTLS_LIBRARY ON CACHE BOOL "" FORCE)
set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "" FORCE)
set(GEN_FILES OFF CACHE BOOL "" FORCE) # release tarball ships pre-generated files, no Python codegen needed

FetchContent_Declare(
        mbedtls
        EXCLUDE_FROM_ALL # we only need tfpsacrypto — don't build mbedtls/mbedx509's full TLS+X.509 stack
        URL https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-4.1.0/mbedtls-4.1.0.tar.bz2
        URL_HASH SHA256=377a09cf8eb81b5fb2707045e5522d5489d3309fed5006c9874e60558fc81d10
)
FetchContent_MakeAvailable(mbedtls)

# Target name differs between an installed MbedTLSConfig.cmake (MbedTLS::...)
# and a source build via add_subdirectory (unprefixed) — pick whichever
# actually exists instead of hardcoding one.
if(TARGET MbedTLS::tfpsacrypto_static)
    set(CTLS_PSA_CRYPTO_LIB MbedTLS::tfpsacrypto_static)
elseif(TARGET MbedTLS::tfpsacrypto)
    set(CTLS_PSA_CRYPTO_LIB MbedTLS::tfpsacrypto)
elseif(TARGET tfpsacrypto_static)
    set(CTLS_PSA_CRYPTO_LIB tfpsacrypto_static)
elseif(TARGET tfpsacrypto)
    set(CTLS_PSA_CRYPTO_LIB tfpsacrypto)
else()
    message(FATAL_ERROR "compact_tls: no tfpsacrypto target found after building Mbed TLS from source")
endif()

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
        CTLS_STREAM=$<BOOL:${CTLS_STREAM}>
        CTLS_DATAGRAM=$<BOOL:${CTLS_DATAGRAM}>
)
target_link_libraries(compact_tls
        ${CTLS_PSA_CRYPTO_LIB}
)

