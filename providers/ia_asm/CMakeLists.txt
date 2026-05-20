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

# x86-64 ISA feature flags.
# GCC/Clang: -march=x86-64-v2 sets the baseline; separate -m flags enable
#   each extension. Apple Clang requires these as separate -m options rather
#   than the +ext suffix that GCC/upstream-LLVM accept.
# MSVC: /arch:AVX2 is the closest level that enables SSE4.x, AES-NI, PCLMUL,
#   and SHA-NI. MSVC exposes all intrinsics for the target arch without needing
#   per-extension flags, so a single /arch: flag suffices.
if(MSVC)
    target_compile_options(${LIB_NAME} INTERFACE /arch:AVX2)
else()
    target_compile_options(${LIB_NAME} INTERFACE
            -march=x86-64-v2
            -maes
            -msha
            -mpclmul
            -mssse3
    )
endif()

# SHA-NI is the Intel hardware SHA-256 acceleration path.
# Set to OFF to fall back to a portable scalar implementation (e.g. to work
# around a compiler bug or run on a runner without SHA-NI support).
option(SAFE_CRYPTO_IA_ASM_SHA_NI "Enable Intel SHA-NI for SHA-256 acceleration" ON)
if(SAFE_CRYPTO_IA_ASM_SHA_NI)
    target_compile_definitions(${LIB_NAME} INTERFACE IA_ASM_SHA_NI_ENABLED)
endif()

# AES-NI is the Intel hardware AES + PCLMULQDQ path (AES-256-GCM).
# Set to OFF to work around a compiler issue where GCC miscompiles the
# intrinsics despite the #pragma GCC target in defs.hpp.
option(SAFE_CRYPTO_IA_ASM_AES_NI "Enable Intel AES-NI for AES-256-GCM acceleration" ON)
if(SAFE_CRYPTO_IA_ASM_AES_NI)
    target_compile_definitions(${LIB_NAME} INTERFACE IA_ASM_AES_NI_ENABLED)
endif()

if(SAFE_CRYPTO_PQC STREQUAL "LIBOQS")
    target_link_libraries(${LIB_NAME} INTERFACE safe_crypto_lib_liboqs)
endif()
