cmake_minimum_required(VERSION 3.31)
project(safe_crypto_lib)

set(CMAKE_CXX_STANDARD 26)

include(FetchContent)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
include(PermGTest)
include(PermMbedTLS)
include(CTest)

add_subdirectory(safe-crypto-lib)
add_subdirectory(providers)
add_subdirectory(safe-crypto-lib-test)
