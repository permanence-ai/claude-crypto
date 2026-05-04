set(EXE_NAME safe_crypto_lib_bench)

add_executable(${EXE_NAME}
        bench_main.cpp
)

target_link_libraries(${EXE_NAME} PRIVATE
        safe_crypto_warnings
        safe_crypto_optimize
)

target_link_libraries(${EXE_NAME} PRIVATE
        safe_crypto_lib
        safe_crypto_lib_openssl      # always included — OpenSSL backend benchmarked regardless of active provider
        safe_crypto_lib_psa_mbedtls  # always included — PSA backend benchmarked regardless of active provider
        benchmark::benchmark
)

# arm_asm backend cannot be compiled for x86_64 (NEON headers).
# Skip it when cross-compiling for IA ASM.
if(NOT SAFE_CRYPTO_ACTIVE_PROVIDER STREQUAL "IA_ASM")
    target_link_libraries(${EXE_NAME} PRIVATE
            safe_crypto_lib_arm_asm  # all three backends benchmarked side-by-side
    )
endif()

if(SAFE_CRYPTO_PQC STREQUAL "LIBOQS")
    target_link_libraries(${EXE_NAME} PRIVATE safe_crypto_lib_liboqs)
    target_link_libraries(${EXE_NAME} PRIVATE $<TARGET_OBJECTS:safe_crypto_lib_dilithium_ntt>)
endif()
