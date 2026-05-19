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
#   SanitizeTSan   — -O1, TSan (thread-safety), full debug info
#   SanitizeLSan   — -O1, LSan (leak detection), full debug info

# ---------------------------------------------------------------------------
# Default build type — choose Debug when the generator is single-config and
# the user has not set CMAKE_BUILD_TYPE.
# ---------------------------------------------------------------------------
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    message(STATUS "Build type not set — defaulting to Debug")
    set(CMAKE_BUILD_TYPE "Debug" CACHE STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
        Debug Release MinSizeRel RelWithDebInfo Sanitize SanitizeTSan SanitizeLSan)
endif()

# ---------------------------------------------------------------------------
# Sanitize build type — propagate flags CMake doesn't know about natively.
# ---------------------------------------------------------------------------
# Use string(JOIN) so the cache variables hold space-separated strings, not
# semicolon-joined CMake lists.  Semicolons in CMAKE_*_FLAGS_* are treated as
# shell command separators by Ninja/Make, breaking the build.
string(JOIN " " _san_compile_str
    "-fsanitize=address,undefined" "-fno-omit-frame-pointer" "-g" "-O1")
string(JOIN " " _san_link_str
    "-fsanitize=address,undefined")

set(CMAKE_C_FLAGS_SANITIZE   "${_san_compile_str}" CACHE STRING "C flags for Sanitize" FORCE)
set(CMAKE_CXX_FLAGS_SANITIZE "${_san_compile_str}" CACHE STRING "C++ flags for Sanitize" FORCE)
set(CMAKE_EXE_LINKER_FLAGS_SANITIZE    "${_san_link_str}" CACHE STRING "Linker flags for Sanitize" FORCE)
set(CMAKE_SHARED_LINKER_FLAGS_SANITIZE "${_san_link_str}" CACHE STRING "Shared linker flags for Sanitize" FORCE)
mark_as_advanced(
    CMAKE_C_FLAGS_SANITIZE
    CMAKE_CXX_FLAGS_SANITIZE
    CMAKE_EXE_LINKER_FLAGS_SANITIZE
    CMAKE_SHARED_LINKER_FLAGS_SANITIZE
)

# ---------------------------------------------------------------------------
# SanitizeTSan build type — ThreadSanitizer (mutually exclusive with ASan).
# ---------------------------------------------------------------------------
string(JOIN " " _tsan_compile_str
    "-fsanitize=thread" "-fno-omit-frame-pointer" "-g" "-O1")
string(JOIN " " _tsan_link_str
    "-fsanitize=thread")

set(CMAKE_C_FLAGS_SANITIZETSAN   "${_tsan_compile_str}" CACHE STRING "C flags for SanitizeTSan" FORCE)
set(CMAKE_CXX_FLAGS_SANITIZETSAN "${_tsan_compile_str}" CACHE STRING "C++ flags for SanitizeTSan" FORCE)
set(CMAKE_EXE_LINKER_FLAGS_SANITIZETSAN    "${_tsan_link_str}" CACHE STRING "Linker flags for SanitizeTSan" FORCE)
set(CMAKE_SHARED_LINKER_FLAGS_SANITIZETSAN "${_tsan_link_str}" CACHE STRING "Shared linker flags for SanitizeTSan" FORCE)
mark_as_advanced(
    CMAKE_C_FLAGS_SANITIZETSAN
    CMAKE_CXX_FLAGS_SANITIZETSAN
    CMAKE_EXE_LINKER_FLAGS_SANITIZETSAN
    CMAKE_SHARED_LINKER_FLAGS_SANITIZETSAN
)

# ---------------------------------------------------------------------------
# SanitizeLSan build type — LeakSanitizer (standalone, requires clang).
# On macOS, system clang does not support standalone LSan; use homebrew clang:
#   cmake -DCMAKE_CXX_COMPILER=/opt/homebrew/opt/llvm/bin/clang++ \
#         -DCMAKE_C_COMPILER=/opt/homebrew/opt/llvm/bin/clang \
#         -DCMAKE_BUILD_TYPE=SanitizeLSan ...
# ---------------------------------------------------------------------------
string(JOIN " " _lsan_compile_str
    "-fsanitize=leak" "-fno-omit-frame-pointer" "-g" "-O1")
string(JOIN " " _lsan_link_str
    "-fsanitize=leak")

set(CMAKE_C_FLAGS_SANITIZELSAN   "${_lsan_compile_str}" CACHE STRING "C flags for SanitizeLSan" FORCE)
set(CMAKE_CXX_FLAGS_SANITIZELSAN "${_lsan_compile_str}" CACHE STRING "C++ flags for SanitizeLSan" FORCE)
set(CMAKE_EXE_LINKER_FLAGS_SANITIZELSAN    "${_lsan_link_str}" CACHE STRING "Linker flags for SanitizeLSan" FORCE)
set(CMAKE_SHARED_LINKER_FLAGS_SANITIZELSAN "${_lsan_link_str}" CACHE STRING "Shared linker flags for SanitizeLSan" FORCE)
mark_as_advanced(
    CMAKE_C_FLAGS_SANITIZELSAN
    CMAKE_CXX_FLAGS_SANITIZELSAN
    CMAKE_EXE_LINKER_FLAGS_SANITIZELSAN
    CMAKE_SHARED_LINKER_FLAGS_SANITIZELSAN
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

# LTO flag — Clang supports thin LTO; GCC only supports fat LTO (-flto).
if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang" OR CMAKE_CXX_COMPILER_ID STREQUAL "AppleClang")
    set(_lto -flto=thin)
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set(_lto -flto)
else()
    set(_lto "")
endif()

# Hardening flags applied to Release and MinSizeRel.
# _FORTIFY_SOURCE=3 requires at least -O1.
# mbranch-protection=standard enables PAC (pointer authentication for return
# addresses) + BTI (branch target identification) on ARMv8.3+; Apple Silicon
# is ARMv8.5-a with PAC hardware so this is a real runtime protection.
# This flag is ARM-only; GCC 12+ rejects it on x86-64 with a hard error.
# fstack-clash-protection is x86-only; it is silently ignored on AArch64 by
# both Apple Clang and upstream LLVM, so it is intentionally omitted.
set(_harden -fstack-protector-strong)
# Determine whether the actual compile target is AArch64.
# On Apple, CMAKE_OSX_ARCHITECTURES is authoritative when set (it can override
# CMAKE_SYSTEM_PROCESSOR, e.g. -DCMAKE_OSX_ARCHITECTURES=x86_64 on Apple Silicon).
# We emit -mbranch-protection=standard only when every target arch is arm64.
if(APPLE AND CMAKE_OSX_ARCHITECTURES)
    # explicit arch list: emit iff it contains arm64 and not x86_64
    if(CMAKE_OSX_ARCHITECTURES MATCHES "(^|;)arm64($|;)" AND
       NOT CMAKE_OSX_ARCHITECTURES MATCHES "(^|;)x86_64($|;)")
        list(APPEND _harden -mbranch-protection=standard)
    endif()
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64)$")
    list(APPEND _harden -mbranch-protection=standard)
endif()
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

    # Sanitize/SanitizeTSan/SanitizeLSan: flags come from the cache variables above.
    # No additional options needed here — CMake injects them via the cache variables.
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
