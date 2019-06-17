cmake_minimum_required(VERSION 3.0)
project(curl-websocket C)

set(CMAKE_C_STANDARD 11)

set(CMAKE_USE_MBEDTLS ON)
set(CMAKE_USE_OPENSSL OFF)

include_directories(.)

add_subdirectory(depends/mbedtls)
include_directories(${MBEDTLS_ROOT_DIR}/include)

add_subdirectory(depends/curl)
include_directories(depends/curl/include)

add_executable(curl-websocket
        curl-websocket-utils.c
        curl-websocket.c
        curl-websocket.h
        main.c)

target_link_libraries(curl-websocket libcurl mbedtls mbedx509 mbedcrypto z pthread)


add_executable(autobahn-testee
        curl-websocket-utils.c
        curl-websocket.c
        curl-websocket.h
        autobahn-testee.c)

target_link_libraries(autobahn-testee libcurl mbedtls mbedx509 mbedcrypto z pthread)
