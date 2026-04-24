include_guard(GLOBAL)

FetchContent_Declare(
        mbedtls
        SYSTEM
        EXCLUDE_FROM_ALL
        GIT_REPOSITORY https://github.com/Mbed-TLS/mbedtls.git
        GIT_TAG 0fe989b6b514192783c469039edd325fd0989806 #mbedtls-4.1.0
)

FetchContent_MakeAvailable(mbedtls)
