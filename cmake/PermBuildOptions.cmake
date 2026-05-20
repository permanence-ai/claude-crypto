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
# Compiler support: GCC, Clang, AppleClang, MSVC.
# All flags are gated on compiler-id so the file is safe to include on any
# of the four supported compilers without unknown-flag errors.
#
# Build types
#   Debug          — no optimisation, full debug info
#   Release        — full speed, LTO, native tune, dead-strip, hardening
#   MinSizeRel     — size-optimised, LTO, dead-strip, hardening
#   RelWithDebInfo — balanced, debug info (profiling / coverage)
#   Sanitize       — ASan + UBSan (GCC/Clang) / ASan (MSVC), debug info
#   SanitizeTSan   — TSan (GCC/Clang only), debug info
#   SanitizeLSan   — LSan standalone (Clang only), debug info

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
# True when the active compiler is GCC or any Clang variant.
set(_is_gcc_or_clang
    "$<OR:$<CXX_COMPILER_ID:GNU>,$<CXX_COMPILER_ID:Clang>,$<CXX_COMPILER_ID:AppleClang>>")
set(_is_msvc "$<CXX_COMPILER_ID:MSVC>")

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
# Sanitize build type — ASan + UBSan (GCC/Clang); ASan only on MSVC 2019+.
# ---------------------------------------------------------------------------
# Use string(JOIN) so the cache variables hold space-separated strings, not
# semicolon-joined CMake lists.  Semicolons in CMAKE_*_FLAGS_* are treated as
# shell command separators by Ninja/Make, breaking the build.
if(MSVC)
    string(JOIN " " _san_compile_str
        "/fsanitize=address" "/Zi" "/O1" "/Oy-")
    set(_san_link_str "")
else()
    string(JOIN " " _san_compile_str
        "-fsanitize=address,undefined" "-fno-omit-frame-pointer" "-g" "-O1")
    string(JOIN " " _san_link_str
        "-fsanitize=address,undefined")
endif()

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
# SanitizeTSan build type — ThreadSanitizer (GCC/Clang only; not on MSVC).
# ---------------------------------------------------------------------------
if(MSVC)
    # MSVC has no TSan; configure as a plain debug build so CMake does not
    # error on an unknown build type if someone selects SanitizeTSan.
    string(JOIN " " _tsan_compile_str "/Zi" "/O1")
    set(_tsan_link_str "")
else()
    string(JOIN " " _tsan_compile_str
        "-fsanitize=thread" "-fno-omit-frame-pointer" "-g" "-O1")
    string(JOIN " " _tsan_link_str
        "-fsanitize=thread")
endif()

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
# SanitizeLSan build type — LeakSanitizer (standalone Clang only).
# On macOS, system clang does not support standalone LSan; use homebrew clang:
#   cmake -DCMAKE_CXX_COMPILER=/opt/homebrew/opt/llvm/bin/clang++ \
#         -DCMAKE_C_COMPILER=/opt/homebrew/opt/llvm/bin/clang \
#         -DCMAKE_BUILD_TYPE=SanitizeLSan ...
# ---------------------------------------------------------------------------
if(MSVC)
    string(JOIN " " _lsan_compile_str "/Zi" "/O1")
    set(_lsan_link_str "")
else()
    string(JOIN " " _lsan_compile_str
        "-fsanitize=leak" "-fno-omit-frame-pointer" "-g" "-O1")
    string(JOIN " " _lsan_link_str
        "-fsanitize=leak")
endif()

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
    # GCC / Clang
    $<${_is_gcc_or_clang}:
        -Wall
        -Wextra
        -Wpedantic
        -Wconversion
        -Wshadow
        -Wnull-dereference
        -Wimplicit-fallthrough
        -Wformat=2
    >
    # MSVC
    $<${_is_msvc}:
        /W4           # broad warning set (equivalent of -Wall -Wextra)
        /w14244       # implicit narrowing conversion (like -Wconversion)
        /w14456       # local variable shadows outer scope (like -Wshadow)
        /w14473       # not enough arguments for format string (like -Wformat)
        /w14505       # unreferenced local function removed
        /wd4068       # unknown pragma — suppresses warnings on #pragma GCC
        /permissive-  # enforce standard conformance
    >
)

# ---------------------------------------------------------------------------
# Optimisation + hardening target
# ---------------------------------------------------------------------------
add_library(safe_crypto_optimize INTERFACE)

# ---------------------------------------------------------------------------
# LTO: thin LTO for Clang, fat LTO for GCC, /GL+/LTCG for MSVC.
# ---------------------------------------------------------------------------
if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang" OR CMAKE_CXX_COMPILER_ID STREQUAL "AppleClang")
    set(_lto_compile -flto=thin)
    set(_lto_link    -flto=thin)
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set(_lto_compile -flto)
    set(_lto_link    -flto)
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    set(_lto_compile /GL)
    set(_lto_link    /LTCG)
else()
    set(_lto_compile "")
    set(_lto_link    "")
endif()

# ---------------------------------------------------------------------------
# Architecture detection — governs -mbranch-protection and -mtune=native.
# On Apple, CMAKE_OSX_ARCHITECTURES is authoritative when set (it can override
# CMAKE_SYSTEM_PROCESSOR, e.g. -DCMAKE_OSX_ARCHITECTURES=x86_64 on Apple Silicon).
# _is_native_arch: true when every requested target arch matches the host CPU.
# _is_aarch64:     true when every requested target arch is arm64/aarch64.
# ---------------------------------------------------------------------------
if(APPLE AND CMAKE_OSX_ARCHITECTURES)
    if(NOT CMAKE_OSX_ARCHITECTURES MATCHES "(^|;)x86_64($|;)")
        set(_is_aarch64     TRUE)
        set(_is_native_arch TRUE)   # native Apple Silicon targeting arm64
    else()
        set(_is_aarch64     FALSE)
        set(_is_native_arch FALSE)  # cross-compiling to x86_64 on Apple Silicon
    endif()
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64)$")
    set(_is_aarch64     TRUE)
    set(_is_native_arch TRUE)
else()
    set(_is_aarch64     FALSE)
    set(_is_native_arch TRUE)       # native x86-64 or other non-Apple host
endif()

# ---------------------------------------------------------------------------
# Hardening flags (GCC/Clang only — MSVC equivalents are on by default).
#   /GS  — stack buffer overrun detection (MSVC default)
#   /sdl — Security Development Lifecycle checks (MSVC default in most configs)
# ---------------------------------------------------------------------------
set(_harden_gcc_clang -fstack-protector-strong)
if(_is_aarch64)
    # -mbranch-protection=standard: PAC + BTI on ARMv8.3+.
    # ARM-only; GCC 12+ rejects it on x86-64 with a hard error.
    list(APPEND _harden_gcc_clang -mbranch-protection=standard)
endif()

# _FORTIFY_SOURCE=3: glibc buffer-overflow detection at -O1+.
# Meaningful only on glibc (Linux); harmless but ignored on macOS/Windows.
set(_harden_defs_gcc_clang -D_FORTIFY_SOURCE=3)

# MSVC hardening: /GS is on by default; /sdl adds extra checks in Release.
set(_harden_msvc /sdl)

# ---------------------------------------------------------------------------
# -mtune=native: only valid when targeting the host CPU.
# Skip on cross-compiles (e.g. -DCMAKE_OSX_ARCHITECTURES=x86_64 on ARM host)
# and on MSVC (no -mtune equivalent; /favor:blend is the closest but rarely
# worth the complexity).
# ---------------------------------------------------------------------------
set(_tune_native_gcc_clang "")
if(_is_native_arch)
    set(_tune_native_gcc_clang -mtune=native)
endif()

# ---------------------------------------------------------------------------
# Assemble per-config option lists.
# ---------------------------------------------------------------------------
target_compile_options(safe_crypto_optimize INTERFACE
    # ----- GCC / Clang -----
    # Debug: no optimisation, full debug info
    $<$<AND:${_is_gcc_or_clang},$<CONFIG:Debug>>:-O0 -g>

    # Release: maximise speed
    $<$<AND:${_is_gcc_or_clang},$<CONFIG:Release>>:
        -O3 ${_tune_native_gcc_clang} ${_lto_compile} ${_harden_gcc_clang}>

    # MinSizeRel: minimise code size
    $<$<AND:${_is_gcc_or_clang},$<CONFIG:MinSizeRel>>:
        -Os ${_lto_compile} ${_harden_gcc_clang}>

    # RelWithDebInfo: balanced — O2 with debug info
    $<$<AND:${_is_gcc_or_clang},$<CONFIG:RelWithDebInfo>>:-O2 -g>

    # Sanitize/TSan/LSan: injected via cache variables above; nothing extra here.

    # ----- MSVC -----
    # Debug
    $<$<AND:${_is_msvc},$<CONFIG:Debug>>:/Od /Zi /RTC1>

    # Release: /O2 = maximise speed; /Oi = enable intrinsics; /GL = whole-program opt
    $<$<AND:${_is_msvc},$<CONFIG:Release>>:/O2 /Oi ${_lto_compile} ${_harden_msvc}>

    # MinSizeRel: /O1 = minimise size
    $<$<AND:${_is_msvc},$<CONFIG:MinSizeRel>>:/O1 ${_lto_compile} ${_harden_msvc}>

    # RelWithDebInfo
    $<$<AND:${_is_msvc},$<CONFIG:RelWithDebInfo>>:/O2 /Zi>

    # Sanitize (ASan; no UBSan on MSVC): injected via cache variables above.
)

target_compile_definitions(safe_crypto_optimize INTERFACE
    # GCC/Clang: FORTIFY_SOURCE hardening in optimised builds
    $<$<AND:${_is_gcc_or_clang},$<CONFIG:Release>>:${_harden_defs_gcc_clang}>
    $<$<AND:${_is_gcc_or_clang},$<CONFIG:MinSizeRel>>:${_harden_defs_gcc_clang}>
)

target_link_options(safe_crypto_optimize INTERFACE
    # GCC / Clang: LTO at link time
    $<$<AND:${_is_gcc_or_clang},$<CONFIG:Release>>:${_lto_link}>
    $<$<AND:${_is_gcc_or_clang},$<CONFIG:MinSizeRel>>:${_lto_link}>

    # GCC / Clang: dead-strip unreferenced sections
    $<$<AND:${_is_gcc_or_clang},$<CONFIG:Release>,$<PLATFORM_ID:Darwin>>:-Wl,-dead_strip>
    $<$<AND:${_is_gcc_or_clang},$<CONFIG:MinSizeRel>,$<PLATFORM_ID:Darwin>>:-Wl,-dead_strip>
    $<$<AND:${_is_gcc_or_clang},$<CONFIG:Release>,$<NOT:$<PLATFORM_ID:Darwin>>,$<NOT:$<PLATFORM_ID:Windows>>>:-Wl,--gc-sections>
    $<$<AND:${_is_gcc_or_clang},$<CONFIG:MinSizeRel>,$<NOT:$<PLATFORM_ID:Darwin>>,$<NOT:$<PLATFORM_ID:Windows>>>:-Wl,--gc-sections>

    # MSVC: LTO (whole-program link) + dead-strip (/OPT:REF)
    $<$<AND:${_is_msvc},$<CONFIG:Release>>:${_lto_link} /OPT:REF /OPT:ICF>
    $<$<AND:${_is_msvc},$<CONFIG:MinSizeRel>>:${_lto_link} /OPT:REF /OPT:ICF>
)
