set(EXE_NAME safe_crypto_lib_bench)

add_executable(${EXE_NAME}
        bench_main.cpp
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
        safe_crypto_lib_arm_asm      # always included — both backends benchmarked side-by-side
        safe_crypto_lib_psa_mbedtls  # always included — PSA backend benchmarked regardless of active provider
        benchmark::benchmark
)
