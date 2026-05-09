# SPDX-License-Identifier: Apache-2.0
set(EXE_NAME safe_crypto_cli_test)

add_executable(${EXE_NAME}
        aead_tests.hpp
        cli_test_runner.hpp
        digest_tests.hpp
        ecdh_tests.hpp
        ecdsa_tests.hpp
        io_tests.hpp
        mac_tests.hpp
        main.cpp
        random_tests.hpp
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

include(GoogleTest)
gtest_discover_tests(${EXE_NAME})
