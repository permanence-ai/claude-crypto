# SPDX-License-Identifier: Apache-2.0
include_guard(GLOBAL)

FetchContent_Declare(
        CLI11
        SYSTEM
        EXCLUDE_FROM_ALL
        GIT_REPOSITORY https://github.com/CLIUtils/CLI11.git
        GIT_TAG v2.6.2
)

set(CLI11_BUILD_TESTS OFF CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(CLI11)
