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

FetchContent_MakeAvailable(googlebenchmark)
