# SPDX-License-Identifier: Apache-2.0
set(EXE_NAME safe_crypto_lib_test)

add_executable(${EXE_NAME}
        aead_tests.hpp
        arm_asm_tests.hpp
        asymmetric_tests.hpp
        chacha20_tests.hpp
        cross_provider_tests.hpp
        crypto_log_tests.hpp
        digests_tests.hpp
        ecc_tests.hpp
        ecdh_tests.hpp
        ia_asm_tests.hpp
        init_tests.hpp
        kdf_tests.hpp
        mac_tests.hpp
        main.cpp
        ml_dsa_tests.hpp
        ml_kem_tests.hpp
        mock_psa_backend.hpp
        pqc_cross_provider_tests.hpp
        psa_error_tests.hpp
        random_tests.hpp
        rsa_bigint_tests.hpp
        rsa_der_tests.hpp
        rsa_keygen_tests.hpp
        rsa_oaep_tests.hpp
        rsa_pss_tests.hpp
        secure_buffer_tests.hpp
        sigma_i_tests.hpp
        sigma_tests.hpp
        slh_dsa_tests.hpp
        test_utils.hpp
)

target_link_libraries(${EXE_NAME} PRIVATE
        safe_crypto_warnings
        safe_crypto_optimize
)

target_link_libraries(${EXE_NAME} PRIVATE
        safe_crypto_lib
        safe_crypto_lib_psa_mbedtls  # MockPsaBackend always needs PSA headers + mbedtls
        gmock
        gtest
)

# arm_asm backend cannot be compiled for x86_64 (NEON headers).
if(SAFE_CRYPTO_ARM_ASM_AVAILABLE)
    target_link_libraries(${EXE_NAME} PRIVATE
            safe_crypto_lib_arm_asm  # cross_provider_tests needs both backends
    )
endif()

# When PQC supplement is enabled, link liboqs into the test binary so that
# pqc_cross_provider_tests.hpp can instantiate ArmAsmBackend with real PQC ops.
if(SAFE_CRYPTO_PQC STREQUAL "LIBOQS")
    target_link_libraries(${EXE_NAME} PRIVATE safe_crypto_lib_liboqs)
    if(TARGET safe_crypto_lib_dilithium_ntt)
        target_link_libraries(${EXE_NAME} PRIVATE $<TARGET_OBJECTS:safe_crypto_lib_dilithium_ntt>)
    endif()
endif()

include(GoogleTest)
gtest_discover_tests(${EXE_NAME})
