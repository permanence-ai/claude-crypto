/*
Copyright Permanence AI, 2026. All rights reserved.

*/

#pragma once

#include <cstddef>

#include <gtest/gtest.h>

#include "digests.hpp"
#include "test_utils.hpp"


class DigestsTests : public ::testing::Test {


};


TEST_F(DigestsTests, Sha384Test01) {
    constexpr std::size_t INPUT_SIZE_BYTES  = 64;
    constexpr std::size_t SHA384_SIZE_BYTES = 48;

    const auto input  = make_random_secure_buffer(INPUT_SIZE_BYTES);
    const auto digest = sha384(input);

    EXPECT_EQ(digest.size(), SHA384_SIZE_BYTES);
}
