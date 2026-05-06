// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Permanence AI

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#include <gtest/gtest.h>

#include "mac.hpp"
#include "test_utils.hpp"


class MacTests : public ::testing::Test {
protected:
    static constexpr std::size_t KEY_SIZE_BYTES     = 64;
    static constexpr std::size_t MESSAGE_SIZE_BYTES = 64;
};


TEST_F(MacTests, Sha256GenerateProducesExpectedSize) {
    const auto key     = make_random_secure_buffer(KEY_SIZE_BYTES);
    const auto message = make_random_secure_buffer(MESSAGE_SIZE_BYTES);

    const auto mac = hmac_generate<ShaVariant::Sha256>(key, message);

    ASSERT_TRUE(mac.has_value());
    EXPECT_EQ(mac->size(), sha256_size_bytes);
}


TEST_F(MacTests, Sha384GenerateProducesExpectedSize) {
    const auto key     = make_random_secure_buffer(KEY_SIZE_BYTES);
    const auto message = make_random_secure_buffer(MESSAGE_SIZE_BYTES);

    const auto mac = hmac_generate<ShaVariant::Sha384>(key, message);

    ASSERT_TRUE(mac.has_value());
    EXPECT_EQ(mac->size(), sha384_size_bytes);
}


TEST_F(MacTests, Sha512GenerateProducesExpectedSize) {
    const auto key     = make_random_secure_buffer(KEY_SIZE_BYTES);
    const auto message = make_random_secure_buffer(MESSAGE_SIZE_BYTES);

    const auto mac = hmac_generate<ShaVariant::Sha512>(key, message);

    ASSERT_TRUE(mac.has_value());
    EXPECT_EQ(mac->size(), sha512_size_bytes);
}


TEST_F(MacTests, Sha256VerifyRoundTrip) {
    const auto key     = make_random_secure_buffer(KEY_SIZE_BYTES);
    const auto message = make_random_secure_buffer(MESSAGE_SIZE_BYTES);

    const auto mac = hmac_generate<ShaVariant::Sha256>(key, message);
    ASSERT_TRUE(mac.has_value());

    const auto result = hmac_verify<ShaVariant::Sha256>(key, message, *mac);

    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(*result);
}


TEST_F(MacTests, Sha384VerifyRoundTrip) {
    const auto key     = make_random_secure_buffer(KEY_SIZE_BYTES);
    const auto message = make_random_secure_buffer(MESSAGE_SIZE_BYTES);

    const auto mac = hmac_generate<ShaVariant::Sha384>(key, message);
    ASSERT_TRUE(mac.has_value());

    const auto result = hmac_verify<ShaVariant::Sha384>(key, message, *mac);

    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(*result);
}


TEST_F(MacTests, Sha512VerifyRoundTrip) {
    const auto key     = make_random_secure_buffer(KEY_SIZE_BYTES);
    const auto message = make_random_secure_buffer(MESSAGE_SIZE_BYTES);

    const auto mac = hmac_generate<ShaVariant::Sha512>(key, message);
    ASSERT_TRUE(mac.has_value());

    const auto result = hmac_verify<ShaVariant::Sha512>(key, message, *mac);

    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(*result);
}


TEST_F(MacTests, Sha3_256GenerateProducesExpectedSize) {
    const auto key     = make_random_secure_buffer(KEY_SIZE_BYTES);
    const auto message = make_random_secure_buffer(MESSAGE_SIZE_BYTES);

    const auto mac = hmac_generate<ShaVariant::Sha3_256>(key, message);

    ASSERT_TRUE(mac.has_value());
    EXPECT_EQ(mac->size(), sha3_256_size_bytes);
}


TEST_F(MacTests, Sha3_384GenerateProducesExpectedSize) {
    const auto key     = make_random_secure_buffer(KEY_SIZE_BYTES);
    const auto message = make_random_secure_buffer(MESSAGE_SIZE_BYTES);

    const auto mac = hmac_generate<ShaVariant::Sha3_384>(key, message);

    ASSERT_TRUE(mac.has_value());
    EXPECT_EQ(mac->size(), sha3_384_size_bytes);
}


TEST_F(MacTests, Sha3_512GenerateProducesExpectedSize) {
    const auto key     = make_random_secure_buffer(KEY_SIZE_BYTES);
    const auto message = make_random_secure_buffer(MESSAGE_SIZE_BYTES);

    const auto mac = hmac_generate<ShaVariant::Sha3_512>(key, message);

    ASSERT_TRUE(mac.has_value());
    EXPECT_EQ(mac->size(), sha3_512_size_bytes);
}


TEST_F(MacTests, Sha3_256VerifyRoundTrip) {
    const auto key     = make_random_secure_buffer(KEY_SIZE_BYTES);
    const auto message = make_random_secure_buffer(MESSAGE_SIZE_BYTES);

    const auto mac = hmac_generate<ShaVariant::Sha3_256>(key, message);
    ASSERT_TRUE(mac.has_value());

    const auto result = hmac_verify<ShaVariant::Sha3_256>(key, message, *mac);

    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(*result);
}


TEST_F(MacTests, Sha3_384VerifyRoundTrip) {
    const auto key     = make_random_secure_buffer(KEY_SIZE_BYTES);
    const auto message = make_random_secure_buffer(MESSAGE_SIZE_BYTES);

    const auto mac = hmac_generate<ShaVariant::Sha3_384>(key, message);
    ASSERT_TRUE(mac.has_value());

    const auto result = hmac_verify<ShaVariant::Sha3_384>(key, message, *mac);

    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(*result);
}


TEST_F(MacTests, Sha3_512VerifyRoundTrip) {
    const auto key     = make_random_secure_buffer(KEY_SIZE_BYTES);
    const auto message = make_random_secure_buffer(MESSAGE_SIZE_BYTES);

    const auto mac = hmac_generate<ShaVariant::Sha3_512>(key, message);
    ASSERT_TRUE(mac.has_value());

    const auto result = hmac_verify<ShaVariant::Sha3_512>(key, message, *mac);

    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(*result);
}


TEST_F(MacTests, VerifyWithWrongKeyFails) {
    const auto key       = make_random_secure_buffer(KEY_SIZE_BYTES);
    const auto wrong_key = make_random_secure_buffer(KEY_SIZE_BYTES);
    const auto message   = make_random_secure_buffer(MESSAGE_SIZE_BYTES);

    const auto mac = hmac_generate<ShaVariant::Sha384>(key, message);
    ASSERT_TRUE(mac.has_value());

    const auto result = hmac_verify<ShaVariant::Sha384>(wrong_key, message, *mac);

    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(*result);
}


TEST_F(MacTests, VerifyWithTamperedMessageFails) {
    constexpr CryptoByte TAMPER_BYTE = 0xFF;

    const auto key = make_random_secure_buffer(KEY_SIZE_BYTES);
    auto message   = make_random_secure_buffer(MESSAGE_SIZE_BYTES);

    const auto mac = hmac_generate<ShaVariant::Sha384>(key, message);
    ASSERT_TRUE(mac.has_value());

    std::span(message.data(), message.size()).front() ^= TAMPER_BYTE;

    const auto result = hmac_verify<ShaVariant::Sha384>(key, message, *mac);

    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(*result);
}


TEST_F(MacTests, VerifyWithTamperedMacFails) {
    constexpr CryptoByte TAMPER_BYTE = 0xFF;

    const auto key     = make_random_secure_buffer(KEY_SIZE_BYTES);
    const auto message = make_random_secure_buffer(MESSAGE_SIZE_BYTES);

    auto mac = hmac_generate<ShaVariant::Sha384>(key, message);
    ASSERT_TRUE(mac.has_value());

    std::span(mac->data(), mac->size()).front() ^= TAMPER_BYTE;

    const auto result = hmac_verify<ShaVariant::Sha384>(key, message, *mac);

    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(*result);
}
