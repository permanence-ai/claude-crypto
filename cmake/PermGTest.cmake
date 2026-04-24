include_guard(GLOBAL)

FetchContent_Declare(
        googletest
        SYSTEM
        EXCLUDE_FROM_ALL
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG d144031940543e15423a25ae5a8a74141044862 #Live at head: 11/20/2024
)

# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(googletest)
