cmake_minimum_required(VERSION 3.10)
project(QUIC_SFU)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_BUILD_TYPE Debug)


# 设置 include 目录
include_directories(include)

# 链接 quiche 库
link_directories(lib)

# 添加可执行文件 client
add_executable(client src/client.cpp src/quic/newQUIC.cpp)
target_link_libraries(client quiche pthread dl)

# 添加可执行文件 sfu
add_executable(sfu src/sfu.cpp src/quic/newQUIC.cpp)
target_link_libraries(sfu quiche pthread dl)
