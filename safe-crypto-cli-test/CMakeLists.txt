# SPDX-License-Identifier: Apache-2.0
set(EXE_NAME safe_crypto_cli_test)

add_executable(${EXE_NAME}
        aead_tests.hpp
        cli_test_runner.hpp
        digest_tests.hpp
        ecdh_tests.hpp
        help_tests.hpp
        ecdsa_tests.hpp
        io_tests.hpp
        kdf_tests.hpp
        mac_tests.hpp
        main.cpp
        ml_dsa_tests.hpp
        ml_kem_tests.hpp
        random_tests.hpp
        rsa_tests.hpp
        slh_dsa_tests.hpp
)

target_link_libraries(${EXE_NAME} PRIVATE
        safe_crypto_warnings
        safe_crypto_optimize
        gtest
)

# Inject the path to the scli binary as a compile-time string constant.
# add_dependencies ensures scli is built before the test runs, so a scli build
# failure is reported as a build error rather than a runtime test failure.
target_compile_definitions(${EXE_NAME} PRIVATE
        SCLI_PATH="$<TARGET_FILE:scli>"
)
add_dependencies(${EXE_NAME} scli)

# Propagate provider/PQC feature macros so test guards match the build.
target_link_libraries(${EXE_NAME} PRIVATE safe_crypto_lib)

# When the LIBOQS supplement is enabled, link it so SAFE_CRYPTO_PQC_LIBOQS
# is visible to the test binary regardless of which crypto provider is active.
if(SAFE_CRYPTO_PQC STREQUAL "LIBOQS")
    target_link_libraries(${EXE_NAME} PRIVATE safe_crypto_lib_liboqs)
endif()

include(GoogleTest)
gtest_discover_tests(${EXE_NAME} TEST_PREFIX "CLI.")
