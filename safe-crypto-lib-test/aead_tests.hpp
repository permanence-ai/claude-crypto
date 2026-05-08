// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

#include <gtest/gtest.h>

#include "aead.hpp"
#include "test_utils.hpp"


class AeadTests : public ::testing::Test {
protected:
    static constexpr std::size_t KEY_SIZE_BYTES     = 32;
    static constexpr std::size_t IV_SIZE_BYTES      = 12;
    static constexpr std::size_t GCM_TAG_SIZE_BYTES = 16;
};


TEST_F(AeadTests, EncryptProducesExpectedSizes) {
    constexpr std::size_t PLAINTEXT_SIZE_BYTES = 64;

    const auto key       = make_random_fixed_secure_buffer<KEY_SIZE_BYTES>();
    const auto plaintext = make_random_secure_buffer(PLAINTEXT_SIZE_BYTES);

    const auto result = aes256_gcm_encrypt(key, plaintext);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->iv.size(), IV_SIZE_BYTES);
    EXPECT_EQ(result->ciphertext.size(), plaintext.size() + GCM_TAG_SIZE_BYTES);
}


TEST_F(AeadTests, DecryptRoundTrip) {
    constexpr std::size_t PLAINTEXT_SIZE_BYTES = 128;

    const auto key       = make_random_fixed_secure_buffer<KEY_SIZE_BYTES>();
    const auto plaintext = make_random_secure_buffer(PLAINTEXT_SIZE_BYTES);

    const auto encrypted = aes256_gcm_encrypt(key, plaintext);
    ASSERT_TRUE(encrypted.has_value());

    const auto decrypted = aes256_gcm_decrypt(key, *encrypted);

    ASSERT_TRUE(decrypted.has_value());
    ASSERT_EQ(decrypted->size(), plaintext.size());
    EXPECT_TRUE(std::ranges::equal(
        std::span(plaintext.data(), plaintext.size()),
        std::span(decrypted->data(), decrypted->size())));
}


TEST_F(AeadTests, DecryptRoundTripWithAad) {
    constexpr std::size_t PLAINTEXT_SIZE_BYTES = 256;
    constexpr std::size_t AAD_SIZE_BYTES       = 32;

    const auto key       = make_random_fixed_secure_buffer<KEY_SIZE_BYTES>();
    const auto plaintext = make_random_secure_buffer(PLAINTEXT_SIZE_BYTES);
    auto aad             = std::optional<SecureBuffer>(make_random_secure_buffer(AAD_SIZE_BYTES));

    const auto encrypted = aes256_gcm_encrypt(key, plaintext, aad);
    ASSERT_TRUE(encrypted.has_value());

    const auto decrypted = aes256_gcm_decrypt(key, *encrypted, aad);

    ASSERT_TRUE(decrypted.has_value());
    ASSERT_EQ(decrypted->size(), plaintext.size());
    EXPECT_TRUE(std::ranges::equal(
        std::span(plaintext.data(), plaintext.size()),
        std::span(decrypted->data(), decrypted->size())));
}


TEST_F(AeadTests, DecryptWithWrongKeyFails) {
    constexpr std::size_t PLAINTEXT_SIZE_BYTES = 48;

    const auto key       = make_random_fixed_secure_buffer<KEY_SIZE_BYTES>();
    const auto wrong_key = make_random_fixed_secure_buffer<KEY_SIZE_BYTES>();
    const auto plaintext = make_random_secure_buffer(PLAINTEXT_SIZE_BYTES);

    const auto encrypted = aes256_gcm_encrypt(key, plaintext);
    ASSERT_TRUE(encrypted.has_value());

    const auto decrypted = aes256_gcm_decrypt(wrong_key, *encrypted);

    ASSERT_FALSE(decrypted.has_value());
    EXPECT_EQ(decrypted.error().code(), CryptoErrorCode::DecryptionFailed);
    EXPECT_FALSE(decrypted.error().message().empty());
}


TEST_F(AeadTests, DecryptWithTamperedCiphertextFails) {
    constexpr std::size_t  PLAINTEXT_SIZE_BYTES = 96;
    constexpr CryptoByte TAMPER_BYTE          = 0xFF;

    const auto key       = make_random_fixed_secure_buffer<KEY_SIZE_BYTES>();
    const auto plaintext = make_random_secure_buffer(PLAINTEXT_SIZE_BYTES);

    auto encrypted = aes256_gcm_encrypt(key, plaintext);
    ASSERT_TRUE(encrypted.has_value());

    std::span(encrypted->ciphertext.data(), encrypted->ciphertext.size()).front() ^= TAMPER_BYTE;

    const auto decrypted = aes256_gcm_decrypt(key, *encrypted);

    EXPECT_FALSE(decrypted.has_value());
}


TEST_F(AeadTests, DecryptWithWrongAadFails) {
    constexpr std::size_t PLAINTEXT_SIZE_BYTES = 64;
    constexpr std::size_t AAD_SIZE_BYTES       = 24;

    const auto key       = make_random_fixed_secure_buffer<KEY_SIZE_BYTES>();
    const auto plaintext = make_random_secure_buffer(PLAINTEXT_SIZE_BYTES);
    auto aad             = std::optional<SecureBuffer>(make_random_secure_buffer(AAD_SIZE_BYTES));
    auto wrong_aad       = std::optional<SecureBuffer>(make_random_secure_buffer(AAD_SIZE_BYTES));

    const auto encrypted = aes256_gcm_encrypt(key, plaintext, aad);
    ASSERT_TRUE(encrypted.has_value());

    const auto decrypted = aes256_gcm_decrypt(key, *encrypted, wrong_aad);

    EXPECT_FALSE(decrypted.has_value());
}
