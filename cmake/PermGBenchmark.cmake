# SPDX-License-Identifier: Apache-2.0
include_guard(GLOBAL)

FetchContent_Declare(
        googlebenchmark
        SYSTEM
        EXCLUDE_FROM_ALL
        GIT_REPOSITORY https://github.com/google/benchmark.git
        GIT_TAG 12235e24652fc7f809373e7c11a5f73c5763fc4c # v1.9.1
)

set(BENCHMARK_ENABLE_TESTING      OFF CACHE BOOL "" FORCE)
set(BENCHMARK_ENABLE_INSTALL      OFF CACHE BOOL "" FORCE)
set(BENCHMARK_ENABLE_GTEST_TESTS  OFF CACHE BOOL "" FORCE)

# GCC raises false-positive -Wmaybe-uninitialized in libstdc++ headers included
# by benchmark (std::function internals).  Suppress it for the dependency build.
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set(BENCHMARK_CXX_FLAGS_SAVE "${CMAKE_CXX_FLAGS}")
    string(APPEND CMAKE_CXX_FLAGS " -Wno-maybe-uninitialized")
endif()

FetchContent_MakeAvailable(googlebenchmark)

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set(CMAKE_CXX_FLAGS "${BENCHMARK_CXX_FLAGS_SAVE}")
    unset(BENCHMARK_CXX_FLAGS_SAVE)
endif()
