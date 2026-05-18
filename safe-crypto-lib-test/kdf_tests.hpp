// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <climits>
#include <cstddef>
#include <span>

#include <gtest/gtest.h>

#include "kdf.hpp"
#include "test_utils.hpp"


class KdfTests : public ::testing::Test {


};


TEST_F(KdfTests, HkdfDeriveProducesExpectedSize) {
    constexpr std::size_t OUTPUT_LENGTH = 32;

    const auto result = hkdf_derive(OUTPUT_LENGTH);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), OUTPUT_LENGTH);
}


TEST_F(KdfTests, HkdfDeriveWithIkmRoundTrip) {
    constexpr std::size_t OUTPUT_LENGTH = 32;
    auto ikm = make_random_secure_buffer(OUTPUT_LENGTH * 2);

    const auto result = hkdf_derive(OUTPUT_LENGTH, std::optional<SecureBuffer>(std::move(ikm)));

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), OUTPUT_LENGTH);
}


TEST_F(KdfTests, HkdfDeriveWithIkmTooShortFails) {
    constexpr std::size_t OUTPUT_LENGTH = 32;
    auto ikm = make_random_secure_buffer((OUTPUT_LENGTH * 2) - 1);

    const auto result = hkdf_derive(OUTPUT_LENGTH, std::optional<SecureBuffer>(std::move(ikm)));

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::InvalidArgument);
    EXPECT_FALSE(result.error().message().empty());
}


TEST_F(KdfTests, HkdfDeriveWithSaltSucceeds) {
    constexpr std::size_t OUTPUT_LENGTH = 32;
    constexpr std::size_t SALT_SIZE     = 32;
    auto ikm  = make_random_secure_buffer(OUTPUT_LENGTH * 2);
    auto salt = std::optional<SecureBuffer>(make_random_secure_buffer(SALT_SIZE));

    const auto result = hkdf_derive(OUTPUT_LENGTH,
                                   std::optional<SecureBuffer>(std::move(ikm)),
                                   salt);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), OUTPUT_LENGTH);
}


TEST_F(KdfTests, HkdfDeriveWithIkmExactMinimumSucceeds) {
    constexpr std::size_t OUTPUT_LENGTH = 32;
    auto ikm = make_random_secure_buffer(OUTPUT_LENGTH * 2);

    const auto result = hkdf_derive(OUTPUT_LENGTH, std::optional<SecureBuffer>(std::move(ikm)));

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), OUTPUT_LENGTH);
}


TEST_F(KdfTests, HkdfExpandProducesExpectedSize) {
    constexpr std::size_t OUTPUT_LENGTH = 32;
    constexpr std::size_t PRK_SIZE      = 48;

    const auto prk    = make_random_secure_buffer(PRK_SIZE);
    const auto result = hkdf_expand(OUTPUT_LENGTH, prk);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), OUTPUT_LENGTH);
}


TEST_F(KdfTests, HkdfExpandWithInfoProducesExpectedSize) {
    constexpr std::size_t OUTPUT_LENGTH = 64;
    constexpr std::size_t PRK_SIZE      = 48;
    constexpr std::size_t INFO_SIZE     = 16;

    const auto prk  = make_random_secure_buffer(PRK_SIZE);
    auto info       = make_random_secure_buffer(INFO_SIZE);
    const auto result = hkdf_expand(OUTPUT_LENGTH, prk,
                                   std::optional<SecureBuffer>(std::move(info)));

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), OUTPUT_LENGTH);
}


TEST_F(KdfTests, HkdfDeriveLargeOutputWithAdequateIkmSucceeds) {
    // Use output_length = 128 so that the required IKM is exactly 256 bytes —
    // the smallest raw-key cap across all providers (OpenSSL: 256 bytes).
    // This confirms our output-length guard does not false-reject legal inputs.
    constexpr std::size_t kOutputLen = 128;
    auto ikm = make_random_secure_buffer(kOutputLen * 2);

    const auto result = hkdf_derive(kOutputLen,
                                   std::optional<SecureBuffer>(std::move(ikm)));

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), kOutputLen);
}


TEST_F(KdfTests, HkdfDeriveAboveMaxOutputLengthFails) {
    const auto result = hkdf_derive(hkdf_sha384_max_output_bytes + 1);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::InvalidArgument);
}


TEST_F(KdfTests, HkdfDeriveOverflowSizeFails) {
    const auto result = hkdf_derive(SIZE_MAX);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::InvalidArgument);
}


TEST_F(KdfTests, HkdfExpandAboveMaxOutputLengthFails) {
    constexpr std::size_t PRK_SIZE = 48;
    const auto prk = make_random_secure_buffer(PRK_SIZE);

    const auto result = hkdf_expand(hkdf_sha384_max_output_bytes + 1, prk);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::InvalidArgument);
}


TEST_F(KdfTests, HkdfExpandOverflowSizeFails) {
    constexpr std::size_t PRK_SIZE = 48;
    const auto prk = make_random_secure_buffer(PRK_SIZE);

    const auto result = hkdf_expand(SIZE_MAX, prk);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::InvalidArgument);
}


TEST_F(KdfTests, HkdfExpandDifferentInfoProducesDifferentOutput) {
    constexpr std::size_t OUTPUT_LENGTH = 32;
    constexpr std::size_t PRK_SIZE      = 48;
    constexpr std::size_t INFO_SIZE     = 16;

    const auto prk   = make_random_secure_buffer(PRK_SIZE);
    auto info_a      = make_random_secure_buffer(INFO_SIZE);
    auto info_b      = make_random_secure_buffer(INFO_SIZE);

    const auto result_a = hkdf_expand(OUTPUT_LENGTH, prk,
                                     std::optional<SecureBuffer>(std::move(info_a)));
    const auto result_b = hkdf_expand(OUTPUT_LENGTH, prk,
                                     std::optional<SecureBuffer>(std::move(info_b)));

    ASSERT_TRUE(result_a.has_value());
    ASSERT_TRUE(result_b.has_value());

    EXPECT_FALSE(std::ranges::equal(
        std::span(result_a->data(), result_a->size()),
        std::span(result_b->data(), result_b->size())));
}
