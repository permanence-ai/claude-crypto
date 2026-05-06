// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <algorithm>
#include <cstddef>
#include <span>

#include <gtest/gtest.h>

#include "random.hpp"


class RandomTests : public ::testing::Test {


};


TEST_F(RandomTests, GeneratesBufferOfRequestedSize) {
    constexpr std::size_t SIZE_BYTES = 32;

    const auto result = random_bytes(SIZE_BYTES);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), SIZE_BYTES);
}


TEST_F(RandomTests, GeneratesNonZeroOutput) {
    constexpr std::size_t SIZE_BYTES = 64;

    const auto result = random_bytes(SIZE_BYTES);

    ASSERT_TRUE(result.has_value());

    bool all_zero = true;
    for (const auto byte : std::span(result->data(), result->size())) {
        if (byte != 0) {
            all_zero = false;
            break;
        }
    }
    EXPECT_FALSE(all_zero);
}


TEST_F(RandomTests, GeneratesDifferentOutputEachCall) {
    constexpr std::size_t SIZE_BYTES = 32;

    const auto first  = random_bytes(SIZE_BYTES);
    const auto second = random_bytes(SIZE_BYTES);

    ASSERT_TRUE(first.has_value());
    ASSERT_TRUE(second.has_value());

    EXPECT_FALSE(std::ranges::equal(
        std::span(first->data(),  first->size()),
        std::span(second->data(), second->size())));
}
