# SPDX-License-Identifier: Apache-2.0
# PermBuildOptions.cmake
#
# Defines two INTERFACE targets consumed by all compiled targets in this project:
#
#   safe_crypto_warnings  — diagnostic flags, applied everywhere
#   safe_crypto_optimize  — optimisation + hardening flags, per build type
#
# Usage (in any CMakeLists.txt that has a compiled target):
#
#   target_link_libraries(<target> PRIVATE
#       safe_crypto_warnings
#       safe_crypto_optimize
#   )
#
# Build types
#   Debug          — no optimisation, full debug info
#   Release        — -O3, LTO, native tune, dead-strip, hardening (speed)
#   MinSizeRel     — -Os, LTO, dead-strip, hardening (size)
#   RelWithDebInfo — -O2, debug info (profiling / coverage)
#   Sanitize       — -O1, ASan + UBSan, full debug info (defect detection)

# ---------------------------------------------------------------------------
# Default build type — choose Debug when the generator is single-config and
# the user has not set CMAKE_BUILD_TYPE.
# ---------------------------------------------------------------------------
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    message(STATUS "Build type not set — defaulting to Debug")
    set(CMAKE_BUILD_TYPE "Debug" CACHE STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
        Debug Release MinSizeRel RelWithDebInfo Sanitize)
endif()

# ---------------------------------------------------------------------------
# Sanitize build type — propagate flags CMake doesn't know about natively.
# ---------------------------------------------------------------------------
set(_san_compile -fsanitize=address,undefined -fno-omit-frame-pointer -g -O1)
set(_san_link    -fsanitize=address,undefined)

set(CMAKE_C_FLAGS_SANITIZE   "${_san_compile}" CACHE STRING "C flags for Sanitize")
set(CMAKE_CXX_FLAGS_SANITIZE "${_san_compile}" CACHE STRING "C++ flags for Sanitize")
set(CMAKE_EXE_LINKER_FLAGS_SANITIZE    "${_san_link}" CACHE STRING "Linker flags for Sanitize")
set(CMAKE_SHARED_LINKER_FLAGS_SANITIZE "${_san_link}" CACHE STRING "Shared linker flags for Sanitize")
mark_as_advanced(
    CMAKE_C_FLAGS_SANITIZE
    CMAKE_CXX_FLAGS_SANITIZE
    CMAKE_EXE_LINKER_FLAGS_SANITIZE
    CMAKE_SHARED_LINKER_FLAGS_SANITIZE
)

# ---------------------------------------------------------------------------
# Warnings target
# ---------------------------------------------------------------------------
add_library(safe_crypto_warnings INTERFACE)

target_compile_options(safe_crypto_warnings INTERFACE
    -Wall
    -Wextra
    -Wpedantic
    -Wconversion
    -Wshadow
    -Wnull-dereference
    -Wimplicit-fallthrough
    -Wformat=2
)

# ---------------------------------------------------------------------------
# Optimisation + hardening target
# ---------------------------------------------------------------------------
add_library(safe_crypto_optimize INTERFACE)

# Clang/GCC LTO flag
set(_lto -flto=thin)

# Hardening flags applied to Release and MinSizeRel.
# _FORTIFY_SOURCE=3 requires at least -O1.
# mbranch-protection=standard enables PAC (pointer authentication for return
# addresses) + BTI (branch target identification) on ARMv8.3+; Apple Silicon
# is ARMv8.5-a with PAC hardware so this is a real runtime protection.
# fstack-clash-protection is x86-only; it is silently ignored on AArch64 by
# both Apple Clang and upstream LLVM, so it is intentionally omitted.
set(_harden
    -fstack-protector-strong
    -mbranch-protection=standard
)
set(_harden_defs -D_FORTIFY_SOURCE=3)

target_compile_options(safe_crypto_optimize INTERFACE
    # Debug: no optimisation, full debug info
    $<$<CONFIG:Debug>:-O0 -g>

    # Release: maximise speed — O3, native tuning, LTO, hardening
    $<$<CONFIG:Release>:-O3 -mtune=native ${_lto} ${_harden}>

    # MinSizeRel: minimise code size — Os, LTO, hardening
    $<$<CONFIG:MinSizeRel>:-Os ${_lto} ${_harden}>

    # RelWithDebInfo: balanced — O2 with debug info for profiling/coverage
    $<$<CONFIG:RelWithDebInfo>:-O2 -g>

    # Sanitize: light optimisation, ASan + UBSan (flags come from CMAKE_CXX_FLAGS_SANITIZE)
    # No additional options needed here — CMake injects them via the cache variables above.
)

target_compile_definitions(safe_crypto_optimize INTERFACE
    $<$<CONFIG:Release>:${_harden_defs}>
    $<$<CONFIG:MinSizeRel>:${_harden_defs}>
)

target_link_options(safe_crypto_optimize INTERFACE
    # Enable LTO at link time for Release and MinSizeRel
    $<$<CONFIG:Release>:${_lto}>
    $<$<CONFIG:MinSizeRel>:${_lto}>

    # Dead-strip unreferenced sections
    $<$<AND:$<CONFIG:Release>,$<PLATFORM_ID:Darwin>>:-Wl,-dead_strip>
    $<$<AND:$<CONFIG:MinSizeRel>,$<PLATFORM_ID:Darwin>>:-Wl,-dead_strip>
    $<$<AND:$<CONFIG:Release>,$<NOT:$<PLATFORM_ID:Darwin>>>:-Wl,--gc-sections>
    $<$<AND:$<CONFIG:MinSizeRel>,$<NOT:$<PLATFORM_ID:Darwin>>>:-Wl,--gc-sections>
)
