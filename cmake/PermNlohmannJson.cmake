# SPDX-License-Identifier: Apache-2.0
include_guard(GLOBAL)

FetchContent_Declare(
    nlohmann_json
    SYSTEM
    EXCLUDE_FROM_ALL
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG        v3.11.3
)
set(JSON_BuildTests  OFF CACHE BOOL "" FORCE)
set(JSON_Install     OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(nlohmann_json)
