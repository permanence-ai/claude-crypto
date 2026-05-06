# SPDX-License-Identifier: Apache-2.0
set(LIB_NAME safe_crypto_lib_ia_asm)

add_library(${LIB_NAME} INTERFACE)

target_sources(${LIB_NAME} INTERFACE
        aes256.hpp
        aes256_gcm.hpp
        chacha20.hpp
        chacha20_poly1305.hpp
        defs.hpp
        ecdsa.hpp
        ghash.hpp
        hkdf.hpp
        hmac.hpp
        ia_asm_backend.hpp
        keccak.hpp
        key_store.hpp
        poly1305.hpp
        rsa.hpp
        rsa_oaep.hpp
        rsa_pss.hpp
        sha256.hpp
        sha3.hpp
        sha512.hpp
)

target_include_directories(${LIB_NAME} INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/../../safe-crypto-lib
        ${CMAKE_CURRENT_SOURCE_DIR}/../arm_asm
)

# x86-64 baseline + AES-NI, SHA-NI, PCLMULQDQ.
# Apple Clang requires feature flags as separate -m options rather than
# the +ext suffix that GCC/upstream-LLVM accept on micro-arch level names.
target_compile_options(${LIB_NAME} INTERFACE
        -march=x86-64-v2
        -maes
        -msha
        -mpclmul
        -mssse3
)

if(SAFE_CRYPTO_PQC STREQUAL "LIBOQS")
    target_link_libraries(${LIB_NAME} INTERFACE safe_crypto_lib_liboqs)
endif()
