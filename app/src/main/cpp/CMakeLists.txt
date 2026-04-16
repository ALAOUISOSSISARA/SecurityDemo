cmake_minimum_required(VERSION 3.22.1)

project("securitydemo")

add_library(
        security-lib
        SHARED
        native-lib.cpp)

find_library(
        log-lib
        log)

target_link_libraries(
        security-lib
        ${log-lib})