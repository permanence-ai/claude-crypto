# SPDX-License-Identifier: Apache-2.0
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
        pqc_key_store.hpp
        poly1305.hpp
        random.hpp
        rsa.hpp
        rsa_bigint.hpp
        rsa_der.hpp
        rsa_keygen.hpp
        rsa_oaep.hpp
        rsa_pss.hpp
        sha256.hpp
        sha3.hpp
        sha512.hpp
        target_attr.hpp
)

target_include_directories(${LIB_NAME} INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/../../safe-crypto-lib
)

# ARM Crypto Extensions: AES, SHA2, SHA3, PMULL — only valid on AArch64.
# Skip these flags when configuring x86_64 builds so ARM options do not
# propagate to translation units that include x86-portable ASM-provider helpers.
if(SAFE_CRYPTO_ARM_ASM_AVAILABLE)
    target_compile_options(${LIB_NAME} INTERFACE
            -march=armv8.2-a+crypto+sha3
    )
    target_compile_definitions(${LIB_NAME} INTERFACE SAFE_CRYPTO_ARM_ASM_AVAILABLE)
endif()

if(SAFE_CRYPTO_PQC STREQUAL "LIBOQS")
    target_link_libraries(${LIB_NAME} INTERFACE safe_crypto_lib_liboqs)

    # NEON NTT override for Dilithium (ML-DSA).  Built as an OBJECT library so
    # the translation unit is unconditionally included in any executable that
    # links safe_crypto_lib_dilithium_ntt, ensuring our symbols are resolved
    # before the linker consults liboqs.a.
    if(SAFE_CRYPTO_ARM_ASM_AVAILABLE)
        add_library(safe_crypto_lib_dilithium_ntt OBJECT
                dilithium_ntt_neon.cpp
        )
        target_compile_options(safe_crypto_lib_dilithium_ntt PRIVATE
                -march=armv8.2-a+crypto+sha3
        )
        target_compile_definitions(safe_crypto_lib_dilithium_ntt PRIVATE SAFE_CRYPTO_ARM_ASM_AVAILABLE)
        target_include_directories(safe_crypto_lib_dilithium_ntt PRIVATE
                ${CMAKE_CURRENT_SOURCE_DIR}
        )
        target_link_libraries(safe_crypto_lib_dilithium_ntt PRIVATE
                safe_crypto_warnings
                safe_crypto_optimize
        )
    endif()
endif()
