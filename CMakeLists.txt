cmake_minimum_required(VERSION 3.21)
project(wireSharkTest)

set(CMAKE_CXX_STANDARD 11 )
link_libraries( -lws2_32)
add_executable( wireSharkTest main.cpp)
