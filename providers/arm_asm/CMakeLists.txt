set(LIB_NAME safe_crypto_lib_arm_asm)

add_library(${LIB_NAME} INTERFACE)

target_sources(${LIB_NAME} INTERFACE
        arm_asm_backend.hpp
        sha256.hpp
        sha512.hpp
)

target_include_directories(${LIB_NAME} INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

# ARM Crypto Extensions: AES, SHA2, SHA3, PMULL
target_compile_options(${LIB_NAME} INTERFACE
        -march=armv8.2-a+crypto+sha3
)
