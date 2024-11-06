cmake_minimum_required(VERSION 3.29)
project(pintos_SD C)

set(CMAKE_C_STANDARD 99)
include_directories(src src/lib src/lib/kernel)

add_executable(pintos_SD main.c)
