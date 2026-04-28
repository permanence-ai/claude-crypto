set(LIB_NAME safe_crypto_lib_psa_mbedtls)

add_library(${LIB_NAME} INTERFACE)

target_sources(${LIB_NAME} INTERFACE
        psa_mbedtls_backend.hpp
)

target_include_directories(${LIB_NAME} INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(${LIB_NAME} INTERFACE
        safe_crypto_lib
        mbedtls
)
