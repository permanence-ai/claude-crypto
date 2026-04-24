/*
Copyright Permanence AI, 2026. All rights reserved.

*/

#pragma once

#include <cstddef>

#include <gtest/gtest.h>

#include "kdf.hpp"
#include "test_utils.hpp"


class KdfTests : public ::testing::Test {


};


TEST_F(KdfTests, DeriveKeyProducesExpectedSize) {
    constexpr std::size_t OUTPUT_LENGTH = 32;

    const auto result = derive_key(OUTPUT_LENGTH);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), OUTPUT_LENGTH);
}


TEST_F(KdfTests, DeriveKeyWithIkmRoundTrip) {
    constexpr std::size_t OUTPUT_LENGTH = 32;
    auto ikm = make_random_secure_buffer(OUTPUT_LENGTH * 2);

    const auto result = derive_key(OUTPUT_LENGTH, std::optional<SecureBuffer>(std::move(ikm)));

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), OUTPUT_LENGTH);
}


TEST_F(KdfTests, DeriveKeyWithIkmTooShortFails) {
    constexpr std::size_t OUTPUT_LENGTH = 32;
    auto ikm = make_random_secure_buffer(OUTPUT_LENGTH * 2 - 1);

    const auto result = derive_key(OUTPUT_LENGTH, std::optional<SecureBuffer>(std::move(ikm)));

    EXPECT_FALSE(result.has_value());
}


TEST_F(KdfTests, DeriveKeyWithIkmExactMinimumSucceeds) {
    constexpr std::size_t OUTPUT_LENGTH = 32;
    auto ikm = make_random_secure_buffer(OUTPUT_LENGTH * 2);

    const auto result = derive_key(OUTPUT_LENGTH, std::optional<SecureBuffer>(std::move(ikm)));

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), OUTPUT_LENGTH);
}
