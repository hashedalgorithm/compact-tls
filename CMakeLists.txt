cmake_minimum_required(VERSION 4.1)
project(compact_tls C)

set(CMAKE_C_STANDARD 11)

list(APPEND CMAKE_PREFIX_PATH "/opt/homebrew")

find_package(MbedTLS REQUIRED)

include_directories(include)
include_directories(include/ctls)
include_directories(src)
include_directories(examples)

add_executable(compact_tls
        include/ctls/ctls.h
        include/ctls/internal.h
        include/ctls/types.h
        include/ctls/templates.h
        include/ctls/bytes.h
        include/ctls/config.h
        src/ctls.c
        src/crypto.c
        examples/main.c
        examples/client.c
        src/record.c
        src/record.c
)
target_link_libraries(compact_tls
        MbedTLS::tfpsacrypto
        MbedTLS::mbedtls
)

