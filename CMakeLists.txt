cmake_minimum_required(VERSION 3.31)
project(claude_crypto)

set(CMAKE_CXX_STANDARD 26)

include(FetchContent)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
include(PermGTest)
include(PermMbedTLS)
include(CTest)

add_subdirectory(claude-crypto)
add_subdirectory(claude-crypto-test)
