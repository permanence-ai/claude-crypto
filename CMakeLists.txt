cmake_minimum_required(VERSION 3.31)
project(safe_crypto_lib)

set(CMAKE_CXX_STANDARD 26)

set(SAFE_CRYPTO_ACTIVE_PROVIDER "PSA_MBEDTLS" CACHE STRING
    "Crypto backend provider. One of: PSA_MBEDTLS, ARM_ASM, IA_ASM, OPENSSL")
set_property(CACHE SAFE_CRYPTO_ACTIVE_PROVIDER PROPERTY STRINGS
    "PSA_MBEDTLS"
    "ARM_ASM"
    "IA_ASM"
    "OPENSSL")

set(SAFE_CRYPTO_PQC "NONE" CACHE STRING
    "PQC supplement provider. One of: NONE, LIBOQS")
set_property(CACHE SAFE_CRYPTO_PQC PROPERTY STRINGS "NONE" "LIBOQS")

include(FetchContent)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
include(PermBuildOptions)
include(PermGBenchmark)
include(PermGTest)
include(PermMbedTLS)
if(SAFE_CRYPTO_PQC STREQUAL "LIBOQS")
    include(PermLibOqs)
endif()
include(CTest)

# Providers must be configured before safe-crypto-lib so their targets exist
# when safe-crypto-lib selects and links the active one.
add_subdirectory(providers)
add_subdirectory(safe-crypto-lib)
add_subdirectory(safe-crypto-lib-bench)
add_subdirectory(safe-crypto-lib-test)
