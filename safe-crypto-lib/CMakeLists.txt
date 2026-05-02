set(LIB_NAME safe_crypto_lib)

add_library(${LIB_NAME} INTERFACE)

target_sources(${LIB_NAME} INTERFACE
        aead.hpp
        asymmetric.hpp
        contracts.hpp
        crypto_error.hpp
        crypto_provider.hpp
        defs.hpp
        digests.hpp
        ecc.hpp
        ecdh.hpp
        kdf.hpp
        mac.hpp
        ml_dsa_variant.hpp
        pqc_dsa.hpp
        psa_backend.hpp
        provider.hpp
        random.hpp
        secure_buffer.hpp
        sha_variant.hpp
        sigma.hpp
        sigma_i.hpp
        slh_dsa_variant.hpp
)

target_include_directories(${LIB_NAME} INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

# Propagate the selected provider's library and compile definition to all consumers.
if(SAFE_CRYPTO_ACTIVE_PROVIDER STREQUAL "ARM_ASM")
    target_link_libraries(${LIB_NAME} INTERFACE safe_crypto_lib_arm_asm)
    target_compile_definitions(${LIB_NAME} INTERFACE SAFE_CRYPTO_PROVIDER_ARM_ASM)
elseif(SAFE_CRYPTO_ACTIVE_PROVIDER STREQUAL "IA_ASM")
    target_link_libraries(${LIB_NAME} INTERFACE safe_crypto_lib_ia_asm)
    target_compile_definitions(${LIB_NAME} INTERFACE SAFE_CRYPTO_PROVIDER_IA_ASM)
elseif(SAFE_CRYPTO_ACTIVE_PROVIDER STREQUAL "OPENSSL")
    target_link_libraries(${LIB_NAME} INTERFACE safe_crypto_lib_openssl)
    target_compile_definitions(${LIB_NAME} INTERFACE SAFE_CRYPTO_PROVIDER_OPENSSL)
elseif(SAFE_CRYPTO_ACTIVE_PROVIDER STREQUAL "PSA_MBEDTLS")
    target_link_libraries(${LIB_NAME} INTERFACE safe_crypto_lib_psa_mbedtls)
else()
    message(FATAL_ERROR
        "Unknown SAFE_CRYPTO_ACTIVE_PROVIDER '${SAFE_CRYPTO_ACTIVE_PROVIDER}'. "
        "Valid values: PSA_MBEDTLS, ARM_ASM, IA_ASM, OPENSSL")
endif()
