# SPDX-License-Identifier: Apache-2.0
set(LIB_NAME safe_crypto_lib_openssl)

# Prefer the Homebrew OpenSSL 3 installation on macOS.
if(APPLE)
    find_package(OpenSSL 3.0 REQUIRED
        HINTS /opt/homebrew/opt/openssl@3
    )
else()
    find_package(OpenSSL 3.0 REQUIRED)
endif()

add_library(${LIB_NAME} INTERFACE)

target_sources(${LIB_NAME} INTERFACE
        openssl_backend.hpp
        openssl_key_store.hpp
)

target_include_directories(${LIB_NAME} INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/../../safe-crypto-lib
)

target_link_libraries(${LIB_NAME} INTERFACE OpenSSL::Crypto)
