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
        examples/main.c
        examples/client.c
        include/ctls/bytes.h
        include/ctls/config.h
        include/ctls/crypto.h
        include/ctls/ctls.h
        include/ctls/extensions.h
        include/ctls/hsmg.h
        include/ctls/record.h
        include/ctls/templates.h
        include/ctls/types.h
        src/crypto.c
        src/ctls.c
        src/extensions.c
        src/hsmg.c
        src/record.c
        src/templates.c
)
target_link_libraries(compact_tls
        MbedTLS::tfpsacrypto
        MbedTLS::mbedtls
)

