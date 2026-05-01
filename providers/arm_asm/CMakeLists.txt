set(LIB_NAME safe_crypto_lib_arm_asm)

add_library(${LIB_NAME} INTERFACE)

target_sources(${LIB_NAME} INTERFACE
        aes256.hpp
        aes256_gcm.hpp
        arm_asm_backend.hpp
        chacha20.hpp
        chacha20_poly1305.hpp
        ghash.hpp
        hkdf.hpp
        hmac.hpp
        keccak.hpp
        key_store.hpp
        poly1305.hpp
        random.hpp
        rsa.hpp
        sha256.hpp
        sha3.hpp
        sha512.hpp
)

target_include_directories(${LIB_NAME} INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/../../safe-crypto-lib
)

# RSA operations are delegated to MbedTLS PSA; link it here so PSA headers
# and the mbedtls library are available to the ARM ASM provider.
target_link_libraries(${LIB_NAME} INTERFACE mbedtls)

# ARM Crypto Extensions: AES, SHA2, SHA3, PMULL
target_compile_options(${LIB_NAME} INTERFACE
        -march=armv8.2-a+crypto+sha3
)
