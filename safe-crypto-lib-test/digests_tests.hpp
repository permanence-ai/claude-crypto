/*
Copyright Permanence AI, 2026. All rights reserved.

*/

#pragma once

#include <cstddef>
#include <span>

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
    EXPECT_EQ(digest->size(), sha256_size_bytes);
}


TEST_F(DigestsTests, Sha384ProducesExpectedSize) {
    constexpr std::size_t INPUT_SIZE_BYTES = 64;

    const auto input  = make_random_secure_buffer(INPUT_SIZE_BYTES);
    const auto digest = sha<ShaVariant::Sha384>(input);

    ASSERT_TRUE(digest.has_value());
    EXPECT_EQ(digest->size(), sha384_size_bytes);
}


TEST_F(DigestsTests, Sha512ProducesExpectedSize) {
    constexpr std::size_t INPUT_SIZE_BYTES = 64;

    const auto input  = make_random_secure_buffer(INPUT_SIZE_BYTES);
    const auto digest = sha<ShaVariant::Sha512>(input);

    ASSERT_TRUE(digest.has_value());
    EXPECT_EQ(digest->size(), sha512_size_bytes);
}


TEST_F(DigestsTests, Sha3_256ProducesExpectedSize) {
    constexpr std::size_t INPUT_SIZE_BYTES = 64;

    const auto input  = make_random_secure_buffer(INPUT_SIZE_BYTES);
    const auto digest = sha<ShaVariant::Sha3_256>(input);

    ASSERT_TRUE(digest.has_value());
    EXPECT_EQ(digest->size(), sha3_256_size_bytes);
}


TEST_F(DigestsTests, Sha3_384ProducesExpectedSize) {
    constexpr std::size_t INPUT_SIZE_BYTES = 64;

    const auto input  = make_random_secure_buffer(INPUT_SIZE_BYTES);
    const auto digest = sha<ShaVariant::Sha3_384>(input);

    ASSERT_TRUE(digest.has_value());
    EXPECT_EQ(digest->size(), sha3_384_size_bytes);
}


TEST_F(DigestsTests, Sha3_512ProducesExpectedSize) {
    constexpr std::size_t INPUT_SIZE_BYTES = 64;

    const auto input  = make_random_secure_buffer(INPUT_SIZE_BYTES);
    const auto digest = sha<ShaVariant::Sha3_512>(input);

    ASSERT_TRUE(digest.has_value());
    EXPECT_EQ(digest->size(), sha3_512_size_bytes);
}


TEST_F(DigestsTests, Sha2AndSha3ProduceDifferentDigestsForSameInput) {
    constexpr std::size_t INPUT_SIZE_BYTES = 64;

    const auto input    = make_random_secure_buffer(INPUT_SIZE_BYTES);
    const auto sha2_256 = sha<ShaVariant::Sha256>(input);
    const auto sha3_256 = sha<ShaVariant::Sha3_256>(input);

    ASSERT_TRUE(sha2_256.has_value());
    ASSERT_TRUE(sha3_256.has_value());

    EXPECT_FALSE(std::ranges::equal(
        std::span(sha2_256->data(), sha2_256->size()),
        std::span(sha3_256->data(), sha3_256->size())));
}
