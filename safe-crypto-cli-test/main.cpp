// SPDX-License-Identifier: Apache-2.0

#include <gtest/gtest.h>

#include "aead_tests.hpp"
#include "digest_tests.hpp"
#include "mac_tests.hpp"
#include "random_tests.hpp"


auto main(int argc, char** argv) -> int  // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
