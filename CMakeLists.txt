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
)
target_link_libraries(compact_tls
        MbedTLS::tfpsacrypto
)

