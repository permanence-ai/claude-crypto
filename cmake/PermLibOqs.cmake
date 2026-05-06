# SPDX-License-Identifier: Apache-2.0
include_guard(GLOBAL)

FetchContent_Declare(
        liboqs
        SYSTEM
        EXCLUDE_FROM_ALL
        GIT_REPOSITORY https://github.com/open-quantum-safe/liboqs.git
        GIT_TAG 0.13.0
)

# Disable everything we don't need to keep build time and binary size down.
set(OQS_BUILD_ONLY_LIB        ON  CACHE BOOL "" FORCE)
set(OQS_USE_OPENSSL           OFF CACHE BOOL "" FORCE)
set(OQS_DIST_BUILD            OFF CACHE BOOL "" FORCE)
set(OQS_ENABLE_SIG_SPHINCS    OFF CACHE BOOL "" FORCE)  # we use OpenSSL for SLH-DSA
set(OQS_ENABLE_SIG_DILITHIUM  OFF CACHE BOOL "" FORCE)  # legacy name for ML-DSA in older liboqs
set(OQS_ENABLE_KEM_CLASSIC_MCELIECE OFF CACHE BOOL "" FORCE)
set(OQS_ENABLE_KEM_HQC        OFF CACHE BOOL "" FORCE)
set(OQS_ENABLE_KEM_BIKE       OFF CACHE BOOL "" FORCE)
set(OQS_ENABLE_SIG_FALCON     OFF CACHE BOOL "" FORCE)
set(OQS_ENABLE_SIG_MAYO       OFF CACHE BOOL "" FORCE)
set(OQS_ENABLE_SIG_CROSS      OFF CACHE BOOL "" FORCE)
set(OQS_ENABLE_SIG_SNOVA      OFF CACHE BOOL "" FORCE)
set(OQS_ENABLE_SIG_UOV        OFF CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(liboqs)

# liboqs builds a generated oqsconfig.h under ${liboqs_BINARY_DIR}/include/oqs/.
# The FetchContent target only exports the source tree's src/ directory, so we
# must add the build-tree include/ explicitly so <oqs/oqs.h> resolves correctly.
target_include_directories(oqs INTERFACE
    $<BUILD_INTERFACE:${liboqs_BINARY_DIR}/include>)
