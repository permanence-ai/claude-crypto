/*
Copyright Permanence AI, 2026. All rights reserved.

*/

#pragma once

#include <cstddef>
#include <span>

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
    auto ikm = make_random_secure_buffer((OUTPUT_LENGTH * 2) - 1);

    const auto result = derive_key(OUTPUT_LENGTH, std::optional<SecureBuffer>(std::move(ikm)));

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::InvalidArgument);
    EXPECT_FALSE(result.error().message().empty());
}


TEST_F(KdfTests, DeriveKeyWithSaltSucceeds) {
    constexpr std::size_t OUTPUT_LENGTH = 32;
    constexpr std::size_t SALT_SIZE     = 32;
    auto ikm  = make_random_secure_buffer(OUTPUT_LENGTH * 2);
    auto salt = std::optional<SecureBuffer>(make_random_secure_buffer(SALT_SIZE));

    const auto result = derive_key(OUTPUT_LENGTH,
                                   std::optional<SecureBuffer>(std::move(ikm)),
                                   salt);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), OUTPUT_LENGTH);
}


TEST_F(KdfTests, DeriveKeyWithIkmExactMinimumSucceeds) {
    constexpr std::size_t OUTPUT_LENGTH = 32;
    auto ikm = make_random_secure_buffer(OUTPUT_LENGTH * 2);

    const auto result = derive_key(OUTPUT_LENGTH, std::optional<SecureBuffer>(std::move(ikm)));

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), OUTPUT_LENGTH);
}


TEST_F(KdfTests, ExpandKeyProducesExpectedSize) {
    constexpr std::size_t OUTPUT_LENGTH = 32;
    constexpr std::size_t PRK_SIZE      = 48;

    const auto prk    = make_random_secure_buffer(PRK_SIZE);
    const auto result = expand_key(OUTPUT_LENGTH, prk);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), OUTPUT_LENGTH);
}


TEST_F(KdfTests, ExpandKeyWithInfoProducesExpectedSize) {
    constexpr std::size_t OUTPUT_LENGTH = 64;
    constexpr std::size_t PRK_SIZE      = 48;
    constexpr std::size_t INFO_SIZE     = 16;

    const auto prk  = make_random_secure_buffer(PRK_SIZE);
    auto info       = make_random_secure_buffer(INFO_SIZE);
    const auto result = expand_key(OUTPUT_LENGTH, prk,
                                   std::optional<SecureBuffer>(std::move(info)));

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), OUTPUT_LENGTH);
}


TEST_F(KdfTests, ExpandKeyDifferentInfoProducesDifferentOutput) {
    constexpr std::size_t OUTPUT_LENGTH = 32;
    constexpr std::size_t PRK_SIZE      = 48;
    constexpr std::size_t INFO_SIZE     = 16;

    const auto prk   = make_random_secure_buffer(PRK_SIZE);
    auto info_a      = make_random_secure_buffer(INFO_SIZE);
    auto info_b      = make_random_secure_buffer(INFO_SIZE);

    const auto result_a = expand_key(OUTPUT_LENGTH, prk,
                                     std::optional<SecureBuffer>(std::move(info_a)));
    const auto result_b = expand_key(OUTPUT_LENGTH, prk,
                                     std::optional<SecureBuffer>(std::move(info_b)));

    ASSERT_TRUE(result_a.has_value());
    ASSERT_TRUE(result_b.has_value());

    EXPECT_FALSE(std::ranges::equal(
        std::span(result_a->data(), result_a->size()),
        std::span(result_b->data(), result_b->size())));
}
