set(EXE_NAME claude_crypto_test)

add_executable(${EXE_NAME}
        aead_tests.hpp
        digests_tests.hpp
        init_tests.hpp
        mac_tests.hpp
        main.cpp
        random_tests.hpp
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
        gtest
        claude_crypto
)

include(GoogleTest)
gtest_discover_tests(${EXE_NAME})
