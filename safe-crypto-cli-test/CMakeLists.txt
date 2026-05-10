# SPDX-License-Identifier: Apache-2.0
set(EXE_NAME safe_crypto_cli_test)

add_executable(${EXE_NAME}
        aead_tests.hpp
        cli_test_runner.hpp
        digest_tests.hpp
        ecdh_tests.hpp
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
target_compile_definitions(${EXE_NAME} PRIVATE
        SCLI_PATH="$<TARGET_FILE:scli>"
)

# Propagate provider/PQC feature macros so test guards match the build.
target_link_libraries(${EXE_NAME} PRIVATE safe_crypto_lib)

include(GoogleTest)
gtest_discover_tests(${EXE_NAME})
