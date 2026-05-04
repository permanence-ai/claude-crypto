# PermBuildOptions.cmake
#
# Defines two INTERFACE targets consumed by all compiled targets in this project:
#
#   safe_crypto_warnings  — diagnostic flags, applied everywhere
#   safe_crypto_optimize  — optimisation flags, per build type
#
# Usage (in any CMakeLists.txt that has a compiled target):
#
#   target_link_libraries(<target> PRIVATE
#       safe_crypto_warnings
#       safe_crypto_optimize
#   )
#
# Build types
#   Debug        — no optimisation, full debug info
#   Release      — -O3, LTO, native tune, dead-strip (speed)
#   MinSizeRel   — -Os, LTO, dead-strip (size)
#   RelWithDebInfo — -O2, debug info (profiling / coverage)

# ---------------------------------------------------------------------------
# Default build type — choose Debug when the generator is single-config and
# the user has not set CMAKE_BUILD_TYPE.
# ---------------------------------------------------------------------------
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    message(STATUS "Build type not set — defaulting to Debug")
    set(CMAKE_BUILD_TYPE "Debug" CACHE STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
        Debug Release MinSizeRel RelWithDebInfo)
endif()

# ---------------------------------------------------------------------------
# Warnings target
# ---------------------------------------------------------------------------
add_library(safe_crypto_warnings INTERFACE)

target_compile_options(safe_crypto_warnings INTERFACE
    -Wall
    -Wextra
    -Wpedantic
    -Wconversion
)

# ---------------------------------------------------------------------------
# Optimisation target
# ---------------------------------------------------------------------------
add_library(safe_crypto_optimize INTERFACE)

# Clang/GCC LTO flag
set(_lto -flto=thin)

target_compile_options(safe_crypto_optimize INTERFACE
    # Debug: no optimisation, full debug info
    $<$<CONFIG:Debug>:-O0 -g>

    # Release: maximise speed — O3, native tuning, LTO
    $<$<CONFIG:Release>:-O3 -mtune=native ${_lto}>

    # MinSizeRel: minimise code size — Os, LTO
    $<$<CONFIG:MinSizeRel>:-Os ${_lto}>

    # RelWithDebInfo: balanced — O2 with debug info for profiling/coverage
    $<$<CONFIG:RelWithDebInfo>:-O2 -g>
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
