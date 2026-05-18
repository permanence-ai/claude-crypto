// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#include <gtest/gtest.h>

#include "ecc.hpp"
#include "test_utils.hpp"


class EccTests : public ::testing::Test {
protected:
    static constexpr std::size_t MESSAGE_SIZE_BYTES = 64;
};


TEST_F(EccTests, EcdsaGenerateKeyP256ProducesValidKeyPair) {
    const auto key_pair = ecdsa_generate_key<EcCurve::P256>();

    ASSERT_TRUE(key_pair.has_value());
    EXPECT_FALSE(key_pair->private_key_der.empty());
    EXPECT_FALSE(key_pair->public_key_der.empty());
}


TEST_F(EccTests, EcdsaGenerateKeyP384ProducesValidKeyPair) {
    const auto key_pair = ecdsa_generate_key<EcCurve::P384>();

    ASSERT_TRUE(key_pair.has_value());
    EXPECT_FALSE(key_pair->private_key_der.empty());
    EXPECT_FALSE(key_pair->public_key_der.empty());
}


TEST_F(EccTests, EcdsaGenerateKeyP521ProducesValidKeyPair) {
    const auto key_pair = ecdsa_generate_key<EcCurve::P521>();

    ASSERT_TRUE(key_pair.has_value());
    EXPECT_FALSE(key_pair->private_key_der.empty());
    EXPECT_FALSE(key_pair->public_key_der.empty());
}


TEST_F(EccTests, EcdsaP256SignVerifyRoundTrip) {
    auto key_pair = ecdsa_generate_key<EcCurve::P256>();
    ASSERT_TRUE(key_pair.has_value());

    const auto message   = make_random_secure_buffer(MESSAGE_SIZE_BYTES);
    const auto signature = ecdsa_sign(*key_pair, message);
    ASSERT_TRUE(signature.has_value());

    const EcPublicKey<EcCurve::P256> pub{ .public_key_der = std::move(key_pair->public_key_der) };
    const auto result = ecdsa_verify(pub, message, *signature);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(*result);
}


TEST_F(EccTests, EcdsaP384SignVerifyRoundTrip) {
    auto key_pair = ecdsa_generate_key<EcCurve::P384>();
    ASSERT_TRUE(key_pair.has_value());

    const auto message   = make_random_secure_buffer(MESSAGE_SIZE_BYTES);
    const auto signature = ecdsa_sign(*key_pair, message);
    ASSERT_TRUE(signature.has_value());

    const EcPublicKey<EcCurve::P384> pub{ .public_key_der = std::move(key_pair->public_key_der) };
    const auto result = ecdsa_verify(pub, message, *signature);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(*result);
}


TEST_F(EccTests, EcdsaP521SignVerifyRoundTrip) {
    auto key_pair = ecdsa_generate_key<EcCurve::P521>();
    ASSERT_TRUE(key_pair.has_value());

    const auto message   = make_random_secure_buffer(MESSAGE_SIZE_BYTES);
    const auto signature = ecdsa_sign(*key_pair, message);
    ASSERT_TRUE(signature.has_value());

    const EcPublicKey<EcCurve::P521> pub{ .public_key_der = std::move(key_pair->public_key_der) };
    const auto result = ecdsa_verify(pub, message, *signature);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(*result);
}


TEST_F(EccTests, EcdsaVerifyWithWrongKeyFails) {
    const auto key_pair = ecdsa_generate_key<EcCurve::P256>();
    auto wrong_key_pair = ecdsa_generate_key<EcCurve::P256>();
    ASSERT_TRUE(key_pair.has_value());
    ASSERT_TRUE(wrong_key_pair.has_value());

    const auto message   = make_random_secure_buffer(MESSAGE_SIZE_BYTES);
    const auto signature = ecdsa_sign(*key_pair, message);
    ASSERT_TRUE(signature.has_value());

    const EcPublicKey<EcCurve::P256> wrong_pub{ .public_key_der = std::move(wrong_key_pair->public_key_der) };
    const auto result = ecdsa_verify(wrong_pub, message, *signature);
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(*result);
}


TEST_F(EccTests, EcdsaVerifyWithTamperedMessageFails) {
    constexpr CryptoByte TAMPER_BYTE = 0xFF;

    auto key_pair = ecdsa_generate_key<EcCurve::P256>();
    ASSERT_TRUE(key_pair.has_value());

    auto message         = make_random_secure_buffer(MESSAGE_SIZE_BYTES);
    const auto signature = ecdsa_sign(*key_pair, message);
    ASSERT_TRUE(signature.has_value());

    std::span(message.data(), message.size()).front() ^= TAMPER_BYTE;

    const EcPublicKey<EcCurve::P256> pub{ .public_key_der = std::move(key_pair->public_key_der) };
    const auto result = ecdsa_verify(pub, message, *signature);
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(*result);
}


TEST_F(EccTests, EcdsaVerifyWithTamperedSignatureFails) {
    constexpr CryptoByte TAMPER_BYTE = 0xFF;

    auto key_pair = ecdsa_generate_key<EcCurve::P256>();
    ASSERT_TRUE(key_pair.has_value());

    const auto message = make_random_secure_buffer(MESSAGE_SIZE_BYTES);
    auto signature     = ecdsa_sign(*key_pair, message);
    ASSERT_TRUE(signature.has_value());

    std::span(signature->data(), signature->size()).front() ^= TAMPER_BYTE;

    const EcPublicKey<EcCurve::P256> pub{ .public_key_der = std::move(key_pair->public_key_der) };
    const auto result = ecdsa_verify(pub, message, *signature);
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(*result);
}
