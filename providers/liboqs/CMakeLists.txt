set(LIB_NAME safe_crypto_lib_liboqs)

add_library(${LIB_NAME} INTERFACE)

target_sources(${LIB_NAME} INTERFACE
        liboqs_pqc.hpp
)

target_include_directories(${LIB_NAME} INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/../../safe-crypto-lib
)

target_link_libraries(${LIB_NAME} INTERFACE oqs)

target_compile_definitions(${LIB_NAME} INTERFACE SAFE_CRYPTO_PQC_LIBOQS)
