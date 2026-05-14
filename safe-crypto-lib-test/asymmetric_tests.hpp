// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include <gtest/gtest.h>

#include "asymmetric.hpp"
#include "kdf.hpp"
#include "test_utils.hpp"


class AsymmetricTests : public ::testing::Test {
};


TEST_F(AsymmetricTests, GenerateRsaKey3072ProducesValidKeyPair) {
    const auto key_pair = generate_rsa_key<RsaKeyBits::Bits3072>();

    ASSERT_TRUE(key_pair.has_value());
    EXPECT_FALSE(key_pair->private_key_der.empty());
    EXPECT_FALSE(key_pair->public_key_der.empty());
}


TEST_F(AsymmetricTests, GenerateRsaKey4096ProducesValidKeyPair) {
    const auto key_pair = generate_rsa_key<RsaKeyBits::Bits4096>();

    ASSERT_TRUE(key_pair.has_value());
    EXPECT_FALSE(key_pair->private_key_der.empty());
    EXPECT_FALSE(key_pair->public_key_der.empty());
}


TEST_F(AsymmetricTests, RsaOaep3072EncryptDecryptRoundTrip) {
    constexpr std::size_t PLAINTEXT_SIZE_BYTES = 64;

    auto key_pair = generate_rsa_key<RsaKeyBits::Bits3072>();
    ASSERT_TRUE(key_pair.has_value());

    const auto plaintext = make_random_secure_buffer(PLAINTEXT_SIZE_BYTES);
    const RsaPublicKey<RsaKeyBits::Bits3072> pub{ .public_key_der = std::move(key_pair->public_key_der) };
    const auto ciphertext = rsa_oaep_encrypt(pub, plaintext);
    ASSERT_TRUE(ciphertext.has_value());

    const auto decrypted = rsa_oaep_decrypt(*key_pair, *ciphertext);
    ASSERT_TRUE(decrypted.has_value());
    ASSERT_EQ(decrypted->size(), plaintext.size());

    EXPECT_TRUE(std::ranges::equal(
        std::span(plaintext.data(), plaintext.size()),
        std::span(decrypted->data(), decrypted->size())));
}


TEST_F(AsymmetricTests, RsaOaep4096EncryptDecryptRoundTrip) {
    constexpr std::size_t PLAINTEXT_SIZE_BYTES = 128;

    auto key_pair = generate_rsa_key<RsaKeyBits::Bits4096>();
    ASSERT_TRUE(key_pair.has_value());

    const auto plaintext = make_random_secure_buffer(PLAINTEXT_SIZE_BYTES);
    const RsaPublicKey<RsaKeyBits::Bits4096> pub{ .public_key_der = std::move(key_pair->public_key_der) };
    const auto ciphertext = rsa_oaep_encrypt(pub, plaintext);
    ASSERT_TRUE(ciphertext.has_value());

    const auto decrypted = rsa_oaep_decrypt(*key_pair, *ciphertext);
    ASSERT_TRUE(decrypted.has_value());
    ASSERT_EQ(decrypted->size(), plaintext.size());

    EXPECT_TRUE(std::ranges::equal(
        std::span(plaintext.data(), plaintext.size()),
        std::span(decrypted->data(), decrypted->size())));
}


TEST_F(AsymmetricTests, RsaOaepRoundTripWithLabel) {
    constexpr std::size_t PLAINTEXT_SIZE_BYTES = 48;

    auto key_pair = generate_rsa_key<RsaKeyBits::Bits3072>();
    ASSERT_TRUE(key_pair.has_value());

    const auto plaintext = make_random_secure_buffer(PLAINTEXT_SIZE_BYTES);

    constexpr ByteArray< 4> LABEL_BYTES = {0x01, 0x02, 0x03, 0x04};
    auto make_label = [&]() {
        SecureBuffer buf(LABEL_BYTES.size());
        std::ranges::copy(LABEL_BYTES, buf.begin());
        return std::optional<SecureBuffer>(std::move(buf));
    };

    const RsaPublicKey<RsaKeyBits::Bits3072> pub{ .public_key_der = std::move(key_pair->public_key_der) };
    const auto ciphertext = rsa_oaep_encrypt(pub, plaintext, make_label());
    ASSERT_TRUE(ciphertext.has_value());

    const auto decrypted = rsa_oaep_decrypt(*key_pair, *ciphertext, make_label());
    ASSERT_TRUE(decrypted.has_value());
    ASSERT_EQ(decrypted->size(), plaintext.size());

    EXPECT_TRUE(std::ranges::equal(
        std::span(plaintext.data(), plaintext.size()),
        std::span(decrypted->data(), decrypted->size())));
}


TEST_F(AsymmetricTests, RsaOaepDecryptWithWrongKeyFails) {
    constexpr std::size_t PLAINTEXT_SIZE_BYTES = 32;

    auto key_pair             = generate_rsa_key<RsaKeyBits::Bits3072>();
    const auto wrong_key_pair = generate_rsa_key<RsaKeyBits::Bits3072>();
    ASSERT_TRUE(key_pair.has_value());
    ASSERT_TRUE(wrong_key_pair.has_value());

    const auto plaintext = make_random_secure_buffer(PLAINTEXT_SIZE_BYTES);
    const RsaPublicKey<RsaKeyBits::Bits3072> pub{ .public_key_der = std::move(key_pair->public_key_der) };
    const auto ciphertext = rsa_oaep_encrypt(pub, plaintext);
    ASSERT_TRUE(ciphertext.has_value());

    const auto decrypted = rsa_oaep_decrypt(*wrong_key_pair, *ciphertext);

    ASSERT_FALSE(decrypted.has_value());
    EXPECT_EQ(decrypted.error().code(), CryptoErrorCode::DecryptionFailed);
    EXPECT_FALSE(decrypted.error().message().empty());
}


TEST_F(AsymmetricTests, RsaOaepDecryptWithWrongLabelFails) {
    constexpr std::size_t PLAINTEXT_SIZE_BYTES = 32;

    auto key_pair = generate_rsa_key<RsaKeyBits::Bits3072>();
    ASSERT_TRUE(key_pair.has_value());

    const auto plaintext = make_random_secure_buffer(PLAINTEXT_SIZE_BYTES);

    constexpr ByteArray< 4> LABEL_BYTES       = {0x0A, 0x0B, 0x0C, 0x0D};
    constexpr ByteArray< 4> WRONG_LABEL_BYTES = {0x01, 0x02, 0x03, 0x04};
    auto make_label = [](const auto& bytes) {
        SecureBuffer buf(bytes.size());
        std::ranges::copy(bytes, buf.begin());
        return std::optional<SecureBuffer>(std::move(buf));
    };

    const RsaPublicKey<RsaKeyBits::Bits3072> pub{ .public_key_der = std::move(key_pair->public_key_der) };
    const auto ciphertext = rsa_oaep_encrypt(pub, plaintext, make_label(LABEL_BYTES));
    ASSERT_TRUE(ciphertext.has_value());

    const auto decrypted = rsa_oaep_decrypt(*key_pair, *ciphertext, make_label(WRONG_LABEL_BYTES));

    EXPECT_FALSE(decrypted.has_value());
}


TEST_F(AsymmetricTests, RsaPss3072SignVerifyRoundTrip) {
    constexpr std::size_t MESSAGE_SIZE_BYTES = 128;

    auto key_pair = generate_rsa_key<RsaKeyBits::Bits3072>();
    ASSERT_TRUE(key_pair.has_value());

    const auto message   = make_random_secure_buffer(MESSAGE_SIZE_BYTES);
    const auto signature = rsa_pss_sign(*key_pair, message);
    ASSERT_TRUE(signature.has_value());

    const RsaPublicKey<RsaKeyBits::Bits3072> pub{ .public_key_der = std::move(key_pair->public_key_der) };
    const auto result = rsa_pss_verify(pub, message, *signature);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(*result);
}


TEST_F(AsymmetricTests, RsaPss4096SignVerifyRoundTrip) {
    constexpr std::size_t MESSAGE_SIZE_BYTES = 256;

    auto key_pair = generate_rsa_key<RsaKeyBits::Bits4096>();
    ASSERT_TRUE(key_pair.has_value());

    const auto message   = make_random_secure_buffer(MESSAGE_SIZE_BYTES);
    const auto signature = rsa_pss_sign(*key_pair, message);
    ASSERT_TRUE(signature.has_value());

    const RsaPublicKey<RsaKeyBits::Bits4096> pub{ .public_key_der = std::move(key_pair->public_key_der) };
    const auto result = rsa_pss_verify(pub, message, *signature);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(*result);
}


TEST_F(AsymmetricTests, RsaPssSignProducesExpectedSize) {
    constexpr std::size_t MESSAGE_SIZE_BYTES            = 64;
    constexpr std::size_t EXPECTED_SIGNATURE_SIZE_BYTES = 3072 / 8;

    const auto key_pair = generate_rsa_key<RsaKeyBits::Bits3072>();
    ASSERT_TRUE(key_pair.has_value());

    const auto message   = make_random_secure_buffer(MESSAGE_SIZE_BYTES);
    const auto signature = rsa_pss_sign(*key_pair, message);

    ASSERT_TRUE(signature.has_value());
    EXPECT_EQ(signature->size(), EXPECTED_SIGNATURE_SIZE_BYTES);
}


TEST_F(AsymmetricTests, RsaPssVerifyWithWrongKeyFails) {
    constexpr std::size_t MESSAGE_SIZE_BYTES = 96;

    const auto key_pair       = generate_rsa_key<RsaKeyBits::Bits3072>();
    auto wrong_key_pair       = generate_rsa_key<RsaKeyBits::Bits3072>();
    ASSERT_TRUE(key_pair.has_value());
    ASSERT_TRUE(wrong_key_pair.has_value());

    const auto message   = make_random_secure_buffer(MESSAGE_SIZE_BYTES);
    const auto signature = rsa_pss_sign(*key_pair, message);
    ASSERT_TRUE(signature.has_value());

    const RsaPublicKey<RsaKeyBits::Bits3072> wrong_pub{ .public_key_der = std::move(wrong_key_pair->public_key_der) };
    const auto result = rsa_pss_verify(wrong_pub, message, *signature);
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(*result);
}


TEST_F(AsymmetricTests, RsaPssVerifyWithTamperedMessageFails) {
    constexpr std::size_t  MESSAGE_SIZE_BYTES = 64;
    constexpr CryptoByte TAMPER_BYTE        = 0xFF;

    auto key_pair = generate_rsa_key<RsaKeyBits::Bits3072>();
    ASSERT_TRUE(key_pair.has_value());

    auto message         = make_random_secure_buffer(MESSAGE_SIZE_BYTES);
    const auto signature = rsa_pss_sign(*key_pair, message);
    ASSERT_TRUE(signature.has_value());

    std::span(message.data(), message.size()).front() ^= TAMPER_BYTE;

    const RsaPublicKey<RsaKeyBits::Bits3072> pub{ .public_key_der = std::move(key_pair->public_key_der) };
    const auto result = rsa_pss_verify(pub, message, *signature);
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(*result);
}


TEST_F(AsymmetricTests, RsaPssVerifyWithTamperedSignatureFails) {
    constexpr std::size_t  MESSAGE_SIZE_BYTES = 64;
    constexpr CryptoByte TAMPER_BYTE        = 0xFF;

    auto key_pair = generate_rsa_key<RsaKeyBits::Bits3072>();
    ASSERT_TRUE(key_pair.has_value());

    const auto message = make_random_secure_buffer(MESSAGE_SIZE_BYTES);
    auto signature     = rsa_pss_sign(*key_pair, message);
    ASSERT_TRUE(signature.has_value());

    std::span(signature->data(), signature->size()).front() ^= TAMPER_BYTE;

    const RsaPublicKey<RsaKeyBits::Bits3072> pub{ .public_key_der = std::move(key_pair->public_key_der) };
    const auto result = rsa_pss_verify(pub, message, *signature);
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(*result);
}
