include_guard(GLOBAL)

FetchContent_Declare(
        mbedtls
        SYSTEM
        EXCLUDE_FROM_ALL
        GIT_REPOSITORY https://github.com/Mbed-TLS/mbedtls.git
        GIT_TAG 0fe989b6b514192783c469039edd325fd0989806 #mbedtls-4.1.0
)

# Disable MbedTLS sample programs to avoid target-name collisions with other
# FetchContent dependencies (e.g. the Google Benchmark target is also named
# "benchmark", which conflicts with mbedtls/tf-psa-crypto/programs/test).
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING  OFF CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(mbedtls)
