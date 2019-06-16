cmake_minimum_required(VERSION 3.0)
project(curl_websocket C)

set(CMAKE_C_STANDARD 11)

include_directories(.)

add_executable(curl_websocket
        curl-websocket-utils.c
        curl-websocket.c
        curl-websocket.h
        main.c)

target_link_libraries(curl_websocket curl crypto)


add_executable(autobahn-testee
        curl-websocket-utils.c
        curl-websocket.c
        curl-websocket.h
        autobahn-testee.c)

target_link_libraries(autobahn-testee curl crypto)
