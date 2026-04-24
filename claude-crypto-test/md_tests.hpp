/*
Copyright Permanence AI, 2026. All rights reserved.

*/

#pragma once

#include "claude_crypto.hpp"
#include "test_utils.hpp"

#include <gtest/gtest.h>


class MdTests : public ::testing::Test {


};


TEST_F(MdTests, Sha384Test01) {
    const auto input = make_random_secure_buffer(64);
    const auto digest = sha384(input);

    EXPECT_EQ(digest.size(), 48);
}
