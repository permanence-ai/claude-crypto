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


TEST_F(DigestsTests, Sha256ProducesExpectedSize) {
    constexpr std::size_t INPUT_SIZE_BYTES = 64;

    const auto input  = make_random_secure_buffer(INPUT_SIZE_BYTES);
    const auto digest = sha<ShaVariant::Sha256>(input);

    ASSERT_TRUE(digest.has_value());
    EXPECT_EQ(digest->size(), SHA256_SIZE_BYTES);
}


TEST_F(DigestsTests, Sha384ProducesExpectedSize) {
    constexpr std::size_t INPUT_SIZE_BYTES = 64;

    const auto input  = make_random_secure_buffer(INPUT_SIZE_BYTES);
    const auto digest = sha<ShaVariant::Sha384>(input);

    ASSERT_TRUE(digest.has_value());
    EXPECT_EQ(digest->size(), SHA384_SIZE_BYTES);
}


TEST_F(DigestsTests, Sha512ProducesExpectedSize) {
    constexpr std::size_t INPUT_SIZE_BYTES = 64;

    const auto input  = make_random_secure_buffer(INPUT_SIZE_BYTES);
    const auto digest = sha<ShaVariant::Sha512>(input);

    ASSERT_TRUE(digest.has_value());
    EXPECT_EQ(digest->size(), SHA512_SIZE_BYTES);
}


TEST_F(DigestsTests, DifferentVariantsProduceDifferentDigests) {
    constexpr std::size_t INPUT_SIZE_BYTES = 64;

    const auto input   = make_random_secure_buffer(INPUT_SIZE_BYTES);
    const auto sha256  = sha<ShaVariant::Sha256>(input);
    const auto sha384  = sha<ShaVariant::Sha384>(input);

    ASSERT_TRUE(sha256.has_value());
    ASSERT_TRUE(sha384.has_value());

    // Different output sizes are sufficient to confirm different algorithms ran
    EXPECT_NE(sha256->size(), sha384->size());
}
