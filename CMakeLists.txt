cmake_minimum_required(VERSION 3.0)
project(curl-websocket C)

set(CMAKE_C_STANDARD 11)

include_directories(.)

add_executable(curl-websocket
        curl-websocket-utils.c
        curl-websocket.c
        curl-websocket.h
        main.c)

target_link_libraries(curl-websocket curl mbedtls mbedx509 mbedcrypto z pthread)


add_executable(autobahn-testee
        curl-websocket-utils.c
        curl-websocket.c
        curl-websocket.h
        autobahn-testee.c)

target_link_libraries(autobahn-testee curl mbedtls mbedx509 mbedcrypto z pthread)
