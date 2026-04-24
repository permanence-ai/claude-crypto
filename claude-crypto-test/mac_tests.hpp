/*
Copyright Permanence AI, 2026. All rights reserved.

*/

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#include <gtest/gtest.h>

#include "mac.hpp"
#include "test_utils.hpp"


class MacTests : public ::testing::Test {
protected:
    static constexpr std::size_t KEY_SIZE_BYTES = 48;
    static constexpr std::size_t MAC_SIZE_BYTES = 48;
};


TEST_F(MacTests, GenerateProducesExpectedSize) {
    constexpr std::size_t MESSAGE_SIZE_BYTES = 64;

    const auto key     = make_random_secure_buffer(KEY_SIZE_BYTES);
    const auto message = make_random_secure_buffer(MESSAGE_SIZE_BYTES);

    const auto mac = hmac_sha384_generate(key, message);

    ASSERT_TRUE(mac.has_value());
    EXPECT_EQ(mac->size(), MAC_SIZE_BYTES);
}


TEST_F(MacTests, VerifyRoundTrip) {
    constexpr std::size_t MESSAGE_SIZE_BYTES = 128;

    const auto key     = make_random_secure_buffer(KEY_SIZE_BYTES);
    const auto message = make_random_secure_buffer(MESSAGE_SIZE_BYTES);

    const auto mac = hmac_sha384_generate(key, message);
    ASSERT_TRUE(mac.has_value());

    const auto result = hmac_sha384_verify(key, message, *mac);

    EXPECT_TRUE(result.has_value());
}


TEST_F(MacTests, VerifyWithWrongKeyFails) {
    constexpr std::size_t MESSAGE_SIZE_BYTES = 96;

    const auto key       = make_random_secure_buffer(KEY_SIZE_BYTES);
    const auto wrong_key = make_random_secure_buffer(KEY_SIZE_BYTES);
    const auto message   = make_random_secure_buffer(MESSAGE_SIZE_BYTES);

    const auto mac = hmac_sha384_generate(key, message);
    ASSERT_TRUE(mac.has_value());

    const auto result = hmac_sha384_verify(wrong_key, message, *mac);

    EXPECT_FALSE(result.has_value());
}


TEST_F(MacTests, VerifyWithTamperedMessageFails) {
    constexpr std::size_t  MESSAGE_SIZE_BYTES = 64;
    constexpr std::uint8_t TAMPER_BYTE        = 0xFF;

    const auto key     = make_random_secure_buffer(KEY_SIZE_BYTES);
    auto message       = make_random_secure_buffer(MESSAGE_SIZE_BYTES);

    const auto mac = hmac_sha384_generate(key, message);
    ASSERT_TRUE(mac.has_value());

    std::span(message.data(), message.size()).front() ^= TAMPER_BYTE;

    const auto result = hmac_sha384_verify(key, message, *mac);

    EXPECT_FALSE(result.has_value());
}


TEST_F(MacTests, VerifyWithTamperedMacFails) {
    constexpr std::size_t  MESSAGE_SIZE_BYTES = 48;
    constexpr std::uint8_t TAMPER_BYTE        = 0xFF;

    const auto key     = make_random_secure_buffer(KEY_SIZE_BYTES);
    const auto message = make_random_secure_buffer(MESSAGE_SIZE_BYTES);

    auto mac = hmac_sha384_generate(key, message);
    ASSERT_TRUE(mac.has_value());

    std::span(mac->data(), mac->size()).front() ^= TAMPER_BYTE;

    const auto result = hmac_sha384_verify(key, message, *mac);

    EXPECT_FALSE(result.has_value());
}
