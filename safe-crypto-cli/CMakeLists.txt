# SPDX-License-Identifier: Apache-2.0
set(EXE_NAME scli)

add_executable(${EXE_NAME}
        cli_base64.hpp
        cli_error.hpp
        cli_io.hpp
        cmd_aead.hpp
        cmd_digest.hpp
        cmd_mac.hpp
        cmd_random.hpp
        main.cpp
)

target_link_libraries(${EXE_NAME} PRIVATE
        safe_crypto_warnings
        safe_crypto_optimize
)

target_link_libraries(${EXE_NAME} PRIVATE
        safe_crypto_lib
        CLI11::CLI11
)
