set(EXE_NAME safe_crypto_lib_test)

add_executable(${EXE_NAME}
        aead_tests.hpp
        arm_asm_tests.hpp
        cross_provider_tests.hpp
        asymmetric_tests.hpp
        chacha20_tests.hpp
        digests_tests.hpp
        ecc_tests.hpp
        ecdh_tests.hpp
        init_tests.hpp
        kdf_tests.hpp
        mac_tests.hpp
        main.cpp
        mock_psa_backend.hpp
        psa_error_tests.hpp
        random_tests.hpp
        rsa_bigint_tests.hpp
        rsa_der_tests.hpp
        secure_buffer_tests.hpp
        sigma_i_tests.hpp
        sigma_tests.hpp
        test_utils.hpp
)

target_compile_options(${EXE_NAME} PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -Wconversion
        $<$<CONFIG:Release>:-O3>
)

target_link_libraries(${EXE_NAME} PRIVATE
        safe_crypto_lib
        safe_crypto_lib_arm_asm      # cross_provider_tests always needs both backends
        safe_crypto_lib_psa_mbedtls  # MockPsaBackend always needs PSA headers + mbedtls
        gmock
        gtest
)

include(GoogleTest)
gtest_discover_tests(${EXE_NAME})
