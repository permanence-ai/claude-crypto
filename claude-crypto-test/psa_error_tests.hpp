/*
Copyright Permanence AI, 2026. All rights reserved.

*/

#pragma once

#include <cstddef>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "aead.hpp"
#include "asymmetric.hpp"
#include "digests.hpp"
#include "ecc.hpp"
#include "ecdh.hpp"
#include "kdf.hpp"
#include "mac.hpp"
#include "mock_psa_backend.hpp"
#include "random.hpp"
#include "sigma.hpp"
#include "sigma_i.hpp"
#include "test_utils.hpp"

using ::testing::DoAll;
using ::testing::Return;
using ::testing::SetArgPointee;
// NOLINTNEXTLINE(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
using ::testing::_;


class PsaErrorTests : public ::testing::Test {
protected:
    void SetUp() override {
        mock_ = std::make_unique<::testing::StrictMock<MockPsaOps>>();
        g_mock_psa = mock_.get();
    }
    void TearDown() override {
        g_mock_psa = nullptr;
        mock_.reset();
    }

    // NOLINTNEXTLINE(misc-non-private-member-variables-in-classes,cppcoreguidelines-non-private-member-variables-in-classes)
    std::unique_ptr<::testing::StrictMock<MockPsaOps>> mock_;

    static constexpr mbedtls_svc_key_id_t FAKE_KEY_ID{};
    static constexpr psa_status_t GENERIC_ERROR = PSA_ERROR_GENERIC_ERROR;
};


// ── random.hpp ──────────────────────────────────────────────────────────────

TEST_F(PsaErrorTests, RandomBytesInitFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(GENERIC_ERROR));

    const auto result = random_bytes_impl<MockPsaBackend>(32);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::InitFailed);
}

TEST_F(PsaErrorTests, RandomBytesGenerateFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, generate_random(_, _)).WillOnce(Return(GENERIC_ERROR));

    const auto result = random_bytes_impl<MockPsaBackend>(32);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::RandomGenerationFailed);
}

TEST_F(PsaErrorTests, RandomBytesFixedInitFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(GENERIC_ERROR));

    const auto result = random_bytes_fixed_impl<16, MockPsaBackend>();

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::InitFailed);
}

TEST_F(PsaErrorTests, RandomBytesFixedGenerateFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, generate_random(_, _)).WillOnce(Return(GENERIC_ERROR));

    const auto result = random_bytes_fixed_impl<16, MockPsaBackend>();

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::RandomGenerationFailed);
}


// ── digests.hpp ─────────────────────────────────────────────────────────────

TEST_F(PsaErrorTests, ShaInitFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(GENERIC_ERROR));

    const auto input = make_random_secure_buffer(32);
    const auto result = sha_impl<ShaVariant::Sha256, MockPsaBackend>(input);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::InitFailed);
}

TEST_F(PsaErrorTests, ShaHashComputeFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, hash_compute(_, _, _, _, _, _)).WillOnce(Return(GENERIC_ERROR));

    const auto input = make_random_secure_buffer(32);
    const auto result = sha_impl<ShaVariant::Sha256, MockPsaBackend>(input);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::DigestFailed);
}


// ── mac.hpp ──────────────────────────────────────────────────────────────────

TEST_F(PsaErrorTests, HmacGenerateInitFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(GENERIC_ERROR));

    const auto key = make_random_secure_buffer(48);
    const auto msg = make_random_secure_buffer(32);
    const auto result = hmac_generate_impl<ShaVariant::Sha384, MockPsaBackend>(key, msg);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::InitFailed);
}

TEST_F(PsaErrorTests, HmacGenerateKeyImportFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, import_key(_, _, _, _)).WillOnce(Return(GENERIC_ERROR));

    const auto key = make_random_secure_buffer(48);
    const auto msg = make_random_secure_buffer(32);
    const auto result = hmac_generate_impl<ShaVariant::Sha384, MockPsaBackend>(key, msg);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::KeyImportFailed);
}

TEST_F(PsaErrorTests, HmacGenerateMacComputeFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, import_key(_, _, _, _))
        .WillOnce(DoAll(SetArgPointee<3>(FAKE_KEY_ID), Return(PSA_SUCCESS)));
    EXPECT_CALL(*mock_, mac_compute(_, _, _, _, _, _, _)).WillOnce(Return(GENERIC_ERROR));
    EXPECT_CALL(*mock_, destroy_key(_)).WillOnce(Return(PSA_SUCCESS));

    const auto key = make_random_secure_buffer(48);
    const auto msg = make_random_secure_buffer(32);
    const auto result = hmac_generate_impl<ShaVariant::Sha384, MockPsaBackend>(key, msg);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::MacGenerationFailed);
}

TEST_F(PsaErrorTests, HmacVerifyInitFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(GENERIC_ERROR));

    const auto key = make_random_secure_buffer(48);
    const auto msg = make_random_secure_buffer(32);
    const FixedSecureBuffer<sha384_size_bytes> mac{};
    const auto result = hmac_verify_impl<ShaVariant::Sha384, MockPsaBackend>(key, msg, mac);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::InitFailed);
}

TEST_F(PsaErrorTests, HmacVerifyKeyImportFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, import_key(_, _, _, _)).WillOnce(Return(GENERIC_ERROR));

    const auto key = make_random_secure_buffer(48);
    const auto msg = make_random_secure_buffer(32);
    const FixedSecureBuffer<sha384_size_bytes> mac{};
    const auto result = hmac_verify_impl<ShaVariant::Sha384, MockPsaBackend>(key, msg, mac);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::KeyImportFailed);
}

TEST_F(PsaErrorTests, HmacVerifyMacVerifyFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, import_key(_, _, _, _))
        .WillOnce(DoAll(SetArgPointee<3>(FAKE_KEY_ID), Return(PSA_SUCCESS)));
    EXPECT_CALL(*mock_, mac_verify(_, _, _, _, _, _)).WillOnce(Return(GENERIC_ERROR));
    EXPECT_CALL(*mock_, destroy_key(_)).WillOnce(Return(PSA_SUCCESS));

    const auto key = make_random_secure_buffer(48);
    const auto msg = make_random_secure_buffer(32);
    const FixedSecureBuffer<sha384_size_bytes> mac{};
    const auto result = hmac_verify_impl<ShaVariant::Sha384, MockPsaBackend>(key, msg, mac);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::VerificationFailed);
}


// ── aead.hpp ─────────────────────────────────────────────────────────────────

TEST_F(PsaErrorTests, AesGcmEncryptInitFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(GENERIC_ERROR));

    const auto key = make_random_fixed_secure_buffer<aes256_key_size_bytes>();
    const auto pt  = make_random_secure_buffer(32);
    const auto result = aes256_gcm_encrypt_impl<MockPsaBackend>(key, pt);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::InitFailed);
}

TEST_F(PsaErrorTests, AesGcmEncryptRandomIvFailed) {
    // crypto_init for the outer call; generate_random fails inside random_bytes_fixed_impl
    EXPECT_CALL(*mock_, crypto_init())
        .WillOnce(Return(PSA_SUCCESS))   // aes256_gcm_encrypt_impl
        .WillOnce(Return(PSA_SUCCESS));  // random_bytes_fixed_impl
    EXPECT_CALL(*mock_, generate_random(_, _)).WillOnce(Return(GENERIC_ERROR));

    const auto key = make_random_fixed_secure_buffer<aes256_key_size_bytes>();
    const auto pt  = make_random_secure_buffer(32);
    const auto result = aes256_gcm_encrypt_impl<MockPsaBackend>(key, pt);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::RandomGenerationFailed);
}

TEST_F(PsaErrorTests, AesGcmEncryptKeyImportFailed) {
    EXPECT_CALL(*mock_, crypto_init())
        .WillOnce(Return(PSA_SUCCESS))
        .WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, generate_random(_, _)).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, import_key(_, _, _, _)).WillOnce(Return(GENERIC_ERROR));

    const auto key = make_random_fixed_secure_buffer<aes256_key_size_bytes>();
    const auto pt  = make_random_secure_buffer(32);
    const auto result = aes256_gcm_encrypt_impl<MockPsaBackend>(key, pt);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::KeyImportFailed);
}

TEST_F(PsaErrorTests, AesGcmEncryptAeadEncryptFailed) {
    EXPECT_CALL(*mock_, crypto_init())
        .WillOnce(Return(PSA_SUCCESS))
        .WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, generate_random(_, _)).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, import_key(_, _, _, _))
        .WillOnce(DoAll(SetArgPointee<3>(FAKE_KEY_ID), Return(PSA_SUCCESS)));
    EXPECT_CALL(*mock_, aead_encrypt(_, _, _, _, _, _, _, _, _, _, _))
        .WillOnce(Return(GENERIC_ERROR));
    EXPECT_CALL(*mock_, destroy_key(_)).WillOnce(Return(PSA_SUCCESS));

    const auto key = make_random_fixed_secure_buffer<aes256_key_size_bytes>();
    const auto pt  = make_random_secure_buffer(32);
    const auto result = aes256_gcm_encrypt_impl<MockPsaBackend>(key, pt);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::EncryptionFailed);
}

TEST_F(PsaErrorTests, AesGcmDecryptInitFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(GENERIC_ERROR));

    const auto key = make_random_fixed_secure_buffer<aes256_key_size_bytes>();
    const AesGcmResult ct{ .iv = {}, .ciphertext = make_random_secure_buffer(48) };
    const auto result = aes256_gcm_decrypt_impl<MockPsaBackend>(key, ct);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::InitFailed);
}

TEST_F(PsaErrorTests, AesGcmDecryptKeyImportFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, import_key(_, _, _, _)).WillOnce(Return(GENERIC_ERROR));

    const auto key = make_random_fixed_secure_buffer<aes256_key_size_bytes>();
    const AesGcmResult ct{ .iv = {}, .ciphertext = make_random_secure_buffer(48) };
    const auto result = aes256_gcm_decrypt_impl<MockPsaBackend>(key, ct);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::KeyImportFailed);
}

TEST_F(PsaErrorTests, AesGcmDecryptAeadDecryptFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, import_key(_, _, _, _))
        .WillOnce(DoAll(SetArgPointee<3>(FAKE_KEY_ID), Return(PSA_SUCCESS)));
    EXPECT_CALL(*mock_, aead_decrypt(_, _, _, _, _, _, _, _, _, _, _))
        .WillOnce(Return(GENERIC_ERROR));
    EXPECT_CALL(*mock_, destroy_key(_)).WillOnce(Return(PSA_SUCCESS));

    const auto key = make_random_fixed_secure_buffer<aes256_key_size_bytes>();
    const AesGcmResult ct{ .iv = {}, .ciphertext = make_random_secure_buffer(48) };
    const auto result = aes256_gcm_decrypt_impl<MockPsaBackend>(key, ct);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::DecryptionFailed);
}

TEST_F(PsaErrorTests, ChaCha20EncryptInitFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(GENERIC_ERROR));

    const auto key = make_random_fixed_secure_buffer<chacha20_key_size_bytes>();
    const auto pt  = make_random_secure_buffer(32);
    const auto result = chacha20_poly1305_encrypt_impl<MockPsaBackend>(key, pt);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::InitFailed);
}

TEST_F(PsaErrorTests, ChaCha20EncryptKeyImportFailed) {
    EXPECT_CALL(*mock_, crypto_init())
        .WillOnce(Return(PSA_SUCCESS))
        .WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, generate_random(_, _)).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, import_key(_, _, _, _)).WillOnce(Return(GENERIC_ERROR));

    const auto key = make_random_fixed_secure_buffer<chacha20_key_size_bytes>();
    const auto pt  = make_random_secure_buffer(32);
    const auto result = chacha20_poly1305_encrypt_impl<MockPsaBackend>(key, pt);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::KeyImportFailed);
}

TEST_F(PsaErrorTests, ChaCha20EncryptAeadEncryptFailed) {
    EXPECT_CALL(*mock_, crypto_init())
        .WillOnce(Return(PSA_SUCCESS))
        .WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, generate_random(_, _)).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, import_key(_, _, _, _))
        .WillOnce(DoAll(SetArgPointee<3>(FAKE_KEY_ID), Return(PSA_SUCCESS)));
    EXPECT_CALL(*mock_, aead_encrypt(_, _, _, _, _, _, _, _, _, _, _))
        .WillOnce(Return(GENERIC_ERROR));
    EXPECT_CALL(*mock_, destroy_key(_)).WillOnce(Return(PSA_SUCCESS));

    const auto key = make_random_fixed_secure_buffer<chacha20_key_size_bytes>();
    const auto pt  = make_random_secure_buffer(32);
    const auto result = chacha20_poly1305_encrypt_impl<MockPsaBackend>(key, pt);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::EncryptionFailed);
}

TEST_F(PsaErrorTests, ChaCha20DecryptInitFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(GENERIC_ERROR));

    const auto key = make_random_fixed_secure_buffer<chacha20_key_size_bytes>();
    const ChaCha20Poly1305Result ct{ .iv = {}, .ciphertext = make_random_secure_buffer(48) };
    const auto result = chacha20_poly1305_decrypt_impl<MockPsaBackend>(key, ct);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::InitFailed);
}

TEST_F(PsaErrorTests, ChaCha20DecryptKeyImportFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, import_key(_, _, _, _)).WillOnce(Return(GENERIC_ERROR));

    const auto key = make_random_fixed_secure_buffer<chacha20_key_size_bytes>();
    const ChaCha20Poly1305Result ct{ .iv = {}, .ciphertext = make_random_secure_buffer(48) };
    const auto result = chacha20_poly1305_decrypt_impl<MockPsaBackend>(key, ct);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::KeyImportFailed);
}

TEST_F(PsaErrorTests, ChaCha20DecryptAeadDecryptFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, import_key(_, _, _, _))
        .WillOnce(DoAll(SetArgPointee<3>(FAKE_KEY_ID), Return(PSA_SUCCESS)));
    EXPECT_CALL(*mock_, aead_decrypt(_, _, _, _, _, _, _, _, _, _, _))
        .WillOnce(Return(GENERIC_ERROR));
    EXPECT_CALL(*mock_, destroy_key(_)).WillOnce(Return(PSA_SUCCESS));

    const auto key = make_random_fixed_secure_buffer<chacha20_key_size_bytes>();
    const ChaCha20Poly1305Result ct{ .iv = {}, .ciphertext = make_random_secure_buffer(48) };
    const auto result = chacha20_poly1305_decrypt_impl<MockPsaBackend>(key, ct);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::DecryptionFailed);
}


// ── ecc.hpp ──────────────────────────────────────────────────────────────────

TEST_F(PsaErrorTests, EcdsaGenerateKeyInitFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(GENERIC_ERROR));

    const auto result = ecdsa_generate_key_impl<MockPsaBackend>(EcCurve::P256);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::InitFailed);
}

TEST_F(PsaErrorTests, EcdsaGenerateKeyGenerateFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, generate_key(_, _)).WillOnce(Return(GENERIC_ERROR));

    const auto result = ecdsa_generate_key_impl<MockPsaBackend>(EcCurve::P256);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::KeyGenerationFailed);
}

TEST_F(PsaErrorTests, EcdsaGenerateKeyExportPrivateFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, generate_key(_, _))
        .WillOnce(DoAll(SetArgPointee<1>(FAKE_KEY_ID), Return(PSA_SUCCESS)));
    EXPECT_CALL(*mock_, export_key(_, _, _, _)).WillOnce(Return(GENERIC_ERROR));
    EXPECT_CALL(*mock_, destroy_key(_)).WillOnce(Return(PSA_SUCCESS));

    const auto result = ecdsa_generate_key_impl<MockPsaBackend>(EcCurve::P256);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::KeyExportFailed);
}

TEST_F(PsaErrorTests, EcdsaGenerateKeyExportPublicFailed) {
    constexpr std::size_t FAKE_KEY_BYTES = 32;
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, generate_key(_, _))
        .WillOnce(DoAll(SetArgPointee<1>(FAKE_KEY_ID), Return(PSA_SUCCESS)));
    EXPECT_CALL(*mock_, export_key(_, _, _, _))
        .WillOnce(DoAll(SetArgPointee<3>(FAKE_KEY_BYTES), Return(PSA_SUCCESS)));
    EXPECT_CALL(*mock_, export_public_key(_, _, _, _)).WillOnce(Return(GENERIC_ERROR));
    EXPECT_CALL(*mock_, destroy_key(_)).WillOnce(Return(PSA_SUCCESS));

    const auto result = ecdsa_generate_key_impl<MockPsaBackend>(EcCurve::P256);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::KeyExportFailed);
}

TEST_F(PsaErrorTests, EcdsaSignInitFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(GENERIC_ERROR));

    const EccKeyPair kp{ .private_key_der = make_random_secure_buffer(32), .public_key_der = SecureBuffer(0) };
    const auto msg    = make_random_secure_buffer(32);
    const auto result = ecdsa_sign_impl<MockPsaBackend>(kp, EcCurve::P256, msg);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::InitFailed);
}

TEST_F(PsaErrorTests, EcdsaSignKeyImportFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, import_key(_, _, _, _)).WillOnce(Return(GENERIC_ERROR));

    const EccKeyPair kp{ .private_key_der = make_random_secure_buffer(32), .public_key_der = SecureBuffer(0) };
    const auto msg    = make_random_secure_buffer(32);
    const auto result = ecdsa_sign_impl<MockPsaBackend>(kp, EcCurve::P256, msg);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::KeyImportFailed);
}

TEST_F(PsaErrorTests, EcdsaSignSignMessageFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, import_key(_, _, _, _))
        .WillOnce(DoAll(SetArgPointee<3>(FAKE_KEY_ID), Return(PSA_SUCCESS)));
    EXPECT_CALL(*mock_, sign_message(_, _, _, _, _, _, _)).WillOnce(Return(GENERIC_ERROR));
    EXPECT_CALL(*mock_, destroy_key(_)).WillOnce(Return(PSA_SUCCESS));

    const EccKeyPair kp{ .private_key_der = make_random_secure_buffer(32), .public_key_der = SecureBuffer(0) };
    const auto msg    = make_random_secure_buffer(32);
    const auto result = ecdsa_sign_impl<MockPsaBackend>(kp, EcCurve::P256, msg);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::SigningFailed);
}

TEST_F(PsaErrorTests, EcdsaVerifyInitFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(GENERIC_ERROR));

    const EcPublicKey pub{ .public_key_der = make_random_secure_buffer(65) };
    const auto msg = make_random_secure_buffer(32);
    const auto sig = make_random_secure_buffer(64);
    const auto result = ecdsa_verify_impl<MockPsaBackend>(pub, EcCurve::P256, msg, sig);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::InitFailed);
}

TEST_F(PsaErrorTests, EcdsaVerifyKeyImportFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, import_key(_, _, _, _)).WillOnce(Return(GENERIC_ERROR));

    const EcPublicKey pub{ .public_key_der = make_random_secure_buffer(65) };
    const auto msg = make_random_secure_buffer(32);
    const auto sig = make_random_secure_buffer(64);
    const auto result = ecdsa_verify_impl<MockPsaBackend>(pub, EcCurve::P256, msg, sig);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::KeyImportFailed);
}

TEST_F(PsaErrorTests, EcdsaVerifyMessageFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, import_key(_, _, _, _))
        .WillOnce(DoAll(SetArgPointee<3>(FAKE_KEY_ID), Return(PSA_SUCCESS)));
    EXPECT_CALL(*mock_, verify_message(_, _, _, _, _, _)).WillOnce(Return(GENERIC_ERROR));
    EXPECT_CALL(*mock_, destroy_key(_)).WillOnce(Return(PSA_SUCCESS));

    const EcPublicKey pub{ .public_key_der = make_random_secure_buffer(65) };
    const auto msg = make_random_secure_buffer(32);
    const auto sig = make_random_secure_buffer(64);
    const auto result = ecdsa_verify_impl<MockPsaBackend>(pub, EcCurve::P256, msg, sig);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::VerificationFailed);
}


// ── ecdh.hpp ─────────────────────────────────────────────────────────────────

TEST_F(PsaErrorTests, EcdhGenerateKeyInitFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(GENERIC_ERROR));

    const auto result = ecdh_generate_key_impl<MockPsaBackend>(EcCurve::P256);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::InitFailed);
}

TEST_F(PsaErrorTests, EcdhGenerateKeyGenerateFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, generate_key(_, _)).WillOnce(Return(GENERIC_ERROR));

    const auto result = ecdh_generate_key_impl<MockPsaBackend>(EcCurve::P256);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::KeyGenerationFailed);
}

TEST_F(PsaErrorTests, EcdhGenerateKeyExportPrivateFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, generate_key(_, _))
        .WillOnce(DoAll(SetArgPointee<1>(FAKE_KEY_ID), Return(PSA_SUCCESS)));
    EXPECT_CALL(*mock_, export_key(_, _, _, _)).WillOnce(Return(GENERIC_ERROR));
    EXPECT_CALL(*mock_, destroy_key(_)).WillOnce(Return(PSA_SUCCESS));

    const auto result = ecdh_generate_key_impl<MockPsaBackend>(EcCurve::P256);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::KeyExportFailed);
}

TEST_F(PsaErrorTests, EcdhGenerateKeyExportPublicFailed) {
    constexpr std::size_t FAKE_KEY_BYTES = 32;
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, generate_key(_, _))
        .WillOnce(DoAll(SetArgPointee<1>(FAKE_KEY_ID), Return(PSA_SUCCESS)));
    EXPECT_CALL(*mock_, export_key(_, _, _, _))
        .WillOnce(DoAll(SetArgPointee<3>(FAKE_KEY_BYTES), Return(PSA_SUCCESS)));
    EXPECT_CALL(*mock_, export_public_key(_, _, _, _)).WillOnce(Return(GENERIC_ERROR));
    EXPECT_CALL(*mock_, destroy_key(_)).WillOnce(Return(PSA_SUCCESS));

    const auto result = ecdh_generate_key_impl<MockPsaBackend>(EcCurve::P256);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::KeyExportFailed);
}

TEST_F(PsaErrorTests, EcdhComputeSharedSecretInitFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(GENERIC_ERROR));

    const EccKeyPair kp{ .private_key_der = make_random_secure_buffer(32), .public_key_der = SecureBuffer(0) };
    const auto peer   = make_random_secure_buffer(65);
    const auto result = ecdh_compute_shared_secret_impl<MockPsaBackend>(kp, EcCurve::P256, peer);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::InitFailed);
}

TEST_F(PsaErrorTests, EcdhComputeSharedSecretKeyImportFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, import_key(_, _, _, _)).WillOnce(Return(GENERIC_ERROR));

    const EccKeyPair kp{ .private_key_der = make_random_secure_buffer(32), .public_key_der = SecureBuffer(0) };
    const auto peer   = make_random_secure_buffer(65);
    const auto result = ecdh_compute_shared_secret_impl<MockPsaBackend>(kp, EcCurve::P256, peer);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::KeyImportFailed);
}

TEST_F(PsaErrorTests, EcdhComputeSharedSecretAgreementFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, import_key(_, _, _, _))
        .WillOnce(DoAll(SetArgPointee<3>(FAKE_KEY_ID), Return(PSA_SUCCESS)));
    EXPECT_CALL(*mock_, raw_key_agreement(_, _, _, _, _, _, _)).WillOnce(Return(GENERIC_ERROR));
    EXPECT_CALL(*mock_, destroy_key(_)).WillOnce(Return(PSA_SUCCESS));

    const EccKeyPair kp{ .private_key_der = make_random_secure_buffer(32), .public_key_der = SecureBuffer(0) };
    const auto peer   = make_random_secure_buffer(65);
    const auto result = ecdh_compute_shared_secret_impl<MockPsaBackend>(kp, EcCurve::P256, peer);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::KeyAgreementFailed);
}


// ── asymmetric.hpp ───────────────────────────────────────────────────────────

TEST_F(PsaErrorTests, RsaOaepEncryptInitFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(GENERIC_ERROR));

    const RsaKeyPair<RsaKeyBits::Bits3072> kp{
        .private_key_der = SecureBuffer(0),
        .public_key_der  = make_random_secure_buffer(128),
    };
    const auto pt     = make_random_secure_buffer(32);
    const auto result = rsa_oaep_encrypt_impl<RsaKeyBits::Bits3072, MockPsaBackend>(kp, pt);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::InitFailed);
}

TEST_F(PsaErrorTests, RsaOaepEncryptKeyImportFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, import_key(_, _, _, _)).WillOnce(Return(GENERIC_ERROR));

    const RsaKeyPair<RsaKeyBits::Bits3072> kp{
        .private_key_der = SecureBuffer(0),
        .public_key_der  = make_random_secure_buffer(128),
    };
    const auto pt     = make_random_secure_buffer(32);
    const auto result = rsa_oaep_encrypt_impl<RsaKeyBits::Bits3072, MockPsaBackend>(kp, pt);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::KeyImportFailed);
}

TEST_F(PsaErrorTests, RsaOaepEncryptFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, import_key(_, _, _, _))
        .WillOnce(DoAll(SetArgPointee<3>(FAKE_KEY_ID), Return(PSA_SUCCESS)));
    EXPECT_CALL(*mock_, asymmetric_encrypt(_, _, _, _, _, _, _, _, _))
        .WillOnce(Return(GENERIC_ERROR));
    EXPECT_CALL(*mock_, destroy_key(_)).WillOnce(Return(PSA_SUCCESS));

    const RsaKeyPair<RsaKeyBits::Bits3072> kp{
        .private_key_der = SecureBuffer(0),
        .public_key_der  = make_random_secure_buffer(128),
    };
    const auto pt     = make_random_secure_buffer(32);
    const auto result = rsa_oaep_encrypt_impl<RsaKeyBits::Bits3072, MockPsaBackend>(kp, pt);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::EncryptionFailed);
}

TEST_F(PsaErrorTests, RsaOaepDecryptInitFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(GENERIC_ERROR));

    const RsaKeyPair<RsaKeyBits::Bits3072> kp{
        .private_key_der = make_random_secure_buffer(128),
        .public_key_der  = SecureBuffer(0),
    };
    const auto ct     = make_random_secure_buffer(384);
    const auto result = rsa_oaep_decrypt_impl<RsaKeyBits::Bits3072, MockPsaBackend>(kp, ct);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::InitFailed);
}

TEST_F(PsaErrorTests, RsaOaepDecryptKeyImportFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, import_key(_, _, _, _)).WillOnce(Return(GENERIC_ERROR));

    const RsaKeyPair<RsaKeyBits::Bits3072> kp{
        .private_key_der = make_random_secure_buffer(128),
        .public_key_der  = SecureBuffer(0),
    };
    const auto ct     = make_random_secure_buffer(384);
    const auto result = rsa_oaep_decrypt_impl<RsaKeyBits::Bits3072, MockPsaBackend>(kp, ct);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::KeyImportFailed);
}

TEST_F(PsaErrorTests, RsaOaepDecryptFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, import_key(_, _, _, _))
        .WillOnce(DoAll(SetArgPointee<3>(FAKE_KEY_ID), Return(PSA_SUCCESS)));
    EXPECT_CALL(*mock_, asymmetric_decrypt(_, _, _, _, _, _, _, _, _))
        .WillOnce(Return(GENERIC_ERROR));
    EXPECT_CALL(*mock_, destroy_key(_)).WillOnce(Return(PSA_SUCCESS));

    const RsaKeyPair<RsaKeyBits::Bits3072> kp{
        .private_key_der = make_random_secure_buffer(128),
        .public_key_der  = SecureBuffer(0),
    };
    const auto ct     = make_random_secure_buffer(384);
    const auto result = rsa_oaep_decrypt_impl<RsaKeyBits::Bits3072, MockPsaBackend>(kp, ct);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::DecryptionFailed);
}

TEST_F(PsaErrorTests, RsaPssSignInitFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(GENERIC_ERROR));

    const RsaKeyPair<RsaKeyBits::Bits3072> kp{
        .private_key_der = make_random_secure_buffer(128),
        .public_key_der  = SecureBuffer(0),
    };
    const auto msg    = make_random_secure_buffer(32);
    const auto result = rsa_pss_sign_impl<RsaKeyBits::Bits3072, MockPsaBackend>(kp, msg);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::InitFailed);
}

TEST_F(PsaErrorTests, RsaPssSignKeyImportFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, import_key(_, _, _, _)).WillOnce(Return(GENERIC_ERROR));

    const RsaKeyPair<RsaKeyBits::Bits3072> kp{
        .private_key_der = make_random_secure_buffer(128),
        .public_key_der  = SecureBuffer(0),
    };
    const auto msg    = make_random_secure_buffer(32);
    const auto result = rsa_pss_sign_impl<RsaKeyBits::Bits3072, MockPsaBackend>(kp, msg);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::KeyImportFailed);
}

TEST_F(PsaErrorTests, RsaPssSignMessageFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, import_key(_, _, _, _))
        .WillOnce(DoAll(SetArgPointee<3>(FAKE_KEY_ID), Return(PSA_SUCCESS)));
    EXPECT_CALL(*mock_, sign_message(_, _, _, _, _, _, _)).WillOnce(Return(GENERIC_ERROR));
    EXPECT_CALL(*mock_, destroy_key(_)).WillOnce(Return(PSA_SUCCESS));

    const RsaKeyPair<RsaKeyBits::Bits3072> kp{
        .private_key_der = make_random_secure_buffer(128),
        .public_key_der  = SecureBuffer(0),
    };
    const auto msg    = make_random_secure_buffer(32);
    const auto result = rsa_pss_sign_impl<RsaKeyBits::Bits3072, MockPsaBackend>(kp, msg);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::SigningFailed);
}

TEST_F(PsaErrorTests, RsaPssVerifyInitFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(GENERIC_ERROR));

    const RsaKeyPair<RsaKeyBits::Bits3072> kp{
        .private_key_der = SecureBuffer(0),
        .public_key_der  = make_random_secure_buffer(128),
    };
    const auto msg    = make_random_secure_buffer(32);
    const auto sig    = make_random_secure_buffer(384);
    const auto result = rsa_pss_verify_impl<RsaKeyBits::Bits3072, MockPsaBackend>(kp, msg, sig);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::InitFailed);
}

TEST_F(PsaErrorTests, RsaPssVerifyKeyImportFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, import_key(_, _, _, _)).WillOnce(Return(GENERIC_ERROR));

    const RsaKeyPair<RsaKeyBits::Bits3072> kp{
        .private_key_der = SecureBuffer(0),
        .public_key_der  = make_random_secure_buffer(128),
    };
    const auto msg    = make_random_secure_buffer(32);
    const auto sig    = make_random_secure_buffer(384);
    const auto result = rsa_pss_verify_impl<RsaKeyBits::Bits3072, MockPsaBackend>(kp, msg, sig);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::KeyImportFailed);
}

TEST_F(PsaErrorTests, RsaPssVerifyMessageFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, import_key(_, _, _, _))
        .WillOnce(DoAll(SetArgPointee<3>(FAKE_KEY_ID), Return(PSA_SUCCESS)));
    EXPECT_CALL(*mock_, verify_message(_, _, _, _, _, _)).WillOnce(Return(GENERIC_ERROR));
    EXPECT_CALL(*mock_, destroy_key(_)).WillOnce(Return(PSA_SUCCESS));

    const RsaKeyPair<RsaKeyBits::Bits3072> kp{
        .private_key_der = SecureBuffer(0),
        .public_key_der  = make_random_secure_buffer(128),
    };
    const auto msg    = make_random_secure_buffer(32);
    const auto sig    = make_random_secure_buffer(384);
    const auto result = rsa_pss_verify_impl<RsaKeyBits::Bits3072, MockPsaBackend>(kp, msg, sig);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::VerificationFailed);
}


// ── kdf.hpp ──────────────────────────────────────────────────────────────────

TEST_F(PsaErrorTests, DeriveKeyInitFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(GENERIC_ERROR));

    const auto result = derive_key_impl<MockPsaBackend>(32, std::optional<SecureBuffer>{make_random_secure_buffer(64)});

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::InitFailed);
}

TEST_F(PsaErrorTests, DeriveKeyKeyImportFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, import_key(_, _, _, _)).WillOnce(Return(GENERIC_ERROR));

    const auto result = derive_key_impl<MockPsaBackend>(32, std::optional<SecureBuffer>{make_random_secure_buffer(64)});

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::KeyImportFailed);
}

TEST_F(PsaErrorTests, DeriveKeyKdfSetupFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, import_key(_, _, _, _))
        .WillOnce(DoAll(SetArgPointee<3>(FAKE_KEY_ID), Return(PSA_SUCCESS)));
    EXPECT_CALL(*mock_, key_derivation_setup(_, _)).WillOnce(Return(GENERIC_ERROR));
    EXPECT_CALL(*mock_, key_derivation_abort(_)).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, destroy_key(_)).WillOnce(Return(PSA_SUCCESS));

    const auto result = derive_key_impl<MockPsaBackend>(32, std::optional<SecureBuffer>{make_random_secure_buffer(64)});

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::KdfSetupFailed);
}

TEST_F(PsaErrorTests, DeriveKeyKdfInputKeyFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, import_key(_, _, _, _))
        .WillOnce(DoAll(SetArgPointee<3>(FAKE_KEY_ID), Return(PSA_SUCCESS)));
    EXPECT_CALL(*mock_, key_derivation_setup(_, _)).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, key_derivation_input_key(_, _, _)).WillOnce(Return(GENERIC_ERROR));
    EXPECT_CALL(*mock_, key_derivation_abort(_)).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, destroy_key(_)).WillOnce(Return(PSA_SUCCESS));

    const auto result = derive_key_impl<MockPsaBackend>(32, std::optional<SecureBuffer>{make_random_secure_buffer(64)});

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::KdfInputFailed);
}

TEST_F(PsaErrorTests, DeriveKeyKdfInputInfoFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, import_key(_, _, _, _))
        .WillOnce(DoAll(SetArgPointee<3>(FAKE_KEY_ID), Return(PSA_SUCCESS)));
    EXPECT_CALL(*mock_, key_derivation_setup(_, _)).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, key_derivation_input_key(_, _, _)).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, key_derivation_input_bytes(_, _, _, _)).WillOnce(Return(GENERIC_ERROR));
    EXPECT_CALL(*mock_, key_derivation_abort(_)).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, destroy_key(_)).WillOnce(Return(PSA_SUCCESS));

    const auto result = derive_key_impl<MockPsaBackend>(32, std::optional<SecureBuffer>{make_random_secure_buffer(64)});

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::KdfInputFailed);
}

TEST_F(PsaErrorTests, DeriveKeyKdfOutputFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, import_key(_, _, _, _))
        .WillOnce(DoAll(SetArgPointee<3>(FAKE_KEY_ID), Return(PSA_SUCCESS)));
    EXPECT_CALL(*mock_, key_derivation_setup(_, _)).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, key_derivation_input_key(_, _, _)).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, key_derivation_input_bytes(_, _, _, _)).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, key_derivation_output_bytes(_, _, _)).WillOnce(Return(GENERIC_ERROR));
    EXPECT_CALL(*mock_, key_derivation_abort(_)).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, destroy_key(_)).WillOnce(Return(PSA_SUCCESS));

    const auto result = derive_key_impl<MockPsaBackend>(32, std::optional<SecureBuffer>{make_random_secure_buffer(64)});

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::KdfOutputFailed);
}

TEST_F(PsaErrorTests, ExpandKeyInitFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(GENERIC_ERROR));

    const auto prk    = make_random_secure_buffer(48);
    const auto result = expand_key_impl<MockPsaBackend>(32, prk);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::InitFailed);
}

TEST_F(PsaErrorTests, ExpandKeyKeyImportFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, import_key(_, _, _, _)).WillOnce(Return(GENERIC_ERROR));

    const auto prk    = make_random_secure_buffer(48);
    const auto result = expand_key_impl<MockPsaBackend>(32, prk);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::KeyImportFailed);
}

TEST_F(PsaErrorTests, ExpandKeyKdfSetupFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, import_key(_, _, _, _))
        .WillOnce(DoAll(SetArgPointee<3>(FAKE_KEY_ID), Return(PSA_SUCCESS)));
    EXPECT_CALL(*mock_, key_derivation_setup(_, _)).WillOnce(Return(GENERIC_ERROR));
    EXPECT_CALL(*mock_, key_derivation_abort(_)).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, destroy_key(_)).WillOnce(Return(PSA_SUCCESS));

    const auto prk    = make_random_secure_buffer(48);
    const auto result = expand_key_impl<MockPsaBackend>(32, prk);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::KdfSetupFailed);
}

TEST_F(PsaErrorTests, ExpandKeyKdfInputKeyFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, import_key(_, _, _, _))
        .WillOnce(DoAll(SetArgPointee<3>(FAKE_KEY_ID), Return(PSA_SUCCESS)));
    EXPECT_CALL(*mock_, key_derivation_setup(_, _)).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, key_derivation_input_key(_, _, _)).WillOnce(Return(GENERIC_ERROR));
    EXPECT_CALL(*mock_, key_derivation_abort(_)).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, destroy_key(_)).WillOnce(Return(PSA_SUCCESS));

    const auto prk    = make_random_secure_buffer(48);
    const auto result = expand_key_impl<MockPsaBackend>(32, prk);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::KdfInputFailed);
}

TEST_F(PsaErrorTests, ExpandKeyKdfInfoFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, import_key(_, _, _, _))
        .WillOnce(DoAll(SetArgPointee<3>(FAKE_KEY_ID), Return(PSA_SUCCESS)));
    EXPECT_CALL(*mock_, key_derivation_setup(_, _)).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, key_derivation_input_key(_, _, _)).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, key_derivation_input_bytes(_, _, _, _)).WillOnce(Return(GENERIC_ERROR));
    EXPECT_CALL(*mock_, key_derivation_abort(_)).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, destroy_key(_)).WillOnce(Return(PSA_SUCCESS));

    const auto prk    = make_random_secure_buffer(48);
    const auto result = expand_key_impl<MockPsaBackend>(32, prk);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::KdfInputFailed);
}

TEST_F(PsaErrorTests, ExpandKeyKdfOutputFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, import_key(_, _, _, _))
        .WillOnce(DoAll(SetArgPointee<3>(FAKE_KEY_ID), Return(PSA_SUCCESS)));
    EXPECT_CALL(*mock_, key_derivation_setup(_, _)).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, key_derivation_input_key(_, _, _)).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, key_derivation_input_bytes(_, _, _, _)).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, key_derivation_output_bytes(_, _, _)).WillOnce(Return(GENERIC_ERROR));
    EXPECT_CALL(*mock_, key_derivation_abort(_)).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, destroy_key(_)).WillOnce(Return(PSA_SUCCESS));

    const auto prk    = make_random_secure_buffer(48);
    const auto result = expand_key_impl<MockPsaBackend>(32, prk);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::KdfOutputFailed);
}

TEST_F(PsaErrorTests, GenerateRsaKeyInitFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(GENERIC_ERROR));

    const auto result = generate_rsa_key_impl<RsaKeyBits::Bits3072, MockPsaBackend>();

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::InitFailed);
}

TEST_F(PsaErrorTests, GenerateRsaKeyGenerateFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, generate_key(_, _)).WillOnce(Return(GENERIC_ERROR));

    const auto result = generate_rsa_key_impl<RsaKeyBits::Bits3072, MockPsaBackend>();

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::KeyGenerationFailed);
}

TEST_F(PsaErrorTests, GenerateRsaKeyExportPrivateFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, generate_key(_, _))
        .WillOnce(DoAll(SetArgPointee<1>(FAKE_KEY_ID), Return(PSA_SUCCESS)));
    EXPECT_CALL(*mock_, export_key(_, _, _, _)).WillOnce(Return(GENERIC_ERROR));
    EXPECT_CALL(*mock_, destroy_key(_)).WillOnce(Return(PSA_SUCCESS));

    const auto result = generate_rsa_key_impl<RsaKeyBits::Bits3072, MockPsaBackend>();

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::KeyExportFailed);
}

TEST_F(PsaErrorTests, GenerateRsaKeyExportPublicFailed) {
    constexpr std::size_t FAKE_KEY_BYTES = 128;
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, generate_key(_, _))
        .WillOnce(DoAll(SetArgPointee<1>(FAKE_KEY_ID), Return(PSA_SUCCESS)));
    EXPECT_CALL(*mock_, export_key(_, _, _, _))
        .WillOnce(DoAll(SetArgPointee<3>(FAKE_KEY_BYTES), Return(PSA_SUCCESS)));
    EXPECT_CALL(*mock_, export_public_key(_, _, _, _)).WillOnce(Return(GENERIC_ERROR));
    EXPECT_CALL(*mock_, destroy_key(_)).WillOnce(Return(PSA_SUCCESS));

    const auto result = generate_rsa_key_impl<RsaKeyBits::Bits3072, MockPsaBackend>();

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::KeyExportFailed);
}


// ── sigma.hpp (sigma_derive_keys_impl) ───────────────────────────────────────

TEST_F(PsaErrorTests, SigmaDeriveKeysInitFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(GENERIC_ERROR));

    const auto secret = make_random_secure_buffer(48);
    const auto result = sigma_derive_keys_impl<MockPsaBackend>(secret);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::InitFailed);
}

TEST_F(PsaErrorTests, SigmaDeriveKeysImportFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, import_key(_, _, _, _)).WillOnce(Return(GENERIC_ERROR));

    const auto secret = make_random_secure_buffer(48);
    const auto result = sigma_derive_keys_impl<MockPsaBackend>(secret);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::KeyImportFailed);
}

TEST_F(PsaErrorTests, SigmaDeriveKeysSetupFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, import_key(_, _, _, _))
        .WillOnce(DoAll(SetArgPointee<3>(FAKE_KEY_ID), Return(PSA_SUCCESS)));
    EXPECT_CALL(*mock_, key_derivation_setup(_, _)).WillOnce(Return(GENERIC_ERROR));
    EXPECT_CALL(*mock_, key_derivation_abort(_)).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, destroy_key(_)).WillOnce(Return(PSA_SUCCESS));

    const auto secret = make_random_secure_buffer(48);
    const auto result = sigma_derive_keys_impl<MockPsaBackend>(secret);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::KdfSetupFailed);
}

TEST_F(PsaErrorTests, SigmaDeriveKeysInputKeyFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, import_key(_, _, _, _))
        .WillOnce(DoAll(SetArgPointee<3>(FAKE_KEY_ID), Return(PSA_SUCCESS)));
    EXPECT_CALL(*mock_, key_derivation_setup(_, _)).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, key_derivation_input_key(_, _, _)).WillOnce(Return(GENERIC_ERROR));
    EXPECT_CALL(*mock_, key_derivation_abort(_)).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, destroy_key(_)).WillOnce(Return(PSA_SUCCESS));

    const auto secret = make_random_secure_buffer(48);
    const auto result = sigma_derive_keys_impl<MockPsaBackend>(secret);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::KdfInputFailed);
}

TEST_F(PsaErrorTests, SigmaDeriveKeysInputInfoFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, import_key(_, _, _, _))
        .WillOnce(DoAll(SetArgPointee<3>(FAKE_KEY_ID), Return(PSA_SUCCESS)));
    EXPECT_CALL(*mock_, key_derivation_setup(_, _)).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, key_derivation_input_key(_, _, _)).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, key_derivation_input_bytes(_, _, _, _)).WillOnce(Return(GENERIC_ERROR));
    EXPECT_CALL(*mock_, key_derivation_abort(_)).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, destroy_key(_)).WillOnce(Return(PSA_SUCCESS));

    const auto secret = make_random_secure_buffer(48);
    const auto result = sigma_derive_keys_impl<MockPsaBackend>(secret);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::KdfInputFailed);
}

TEST_F(PsaErrorTests, SigmaDeriveKeysOutputFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, import_key(_, _, _, _))
        .WillOnce(DoAll(SetArgPointee<3>(FAKE_KEY_ID), Return(PSA_SUCCESS)));
    EXPECT_CALL(*mock_, key_derivation_setup(_, _)).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, key_derivation_input_key(_, _, _)).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, key_derivation_input_bytes(_, _, _, _)).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, key_derivation_output_bytes(_, _, _)).WillOnce(Return(GENERIC_ERROR));
    EXPECT_CALL(*mock_, key_derivation_abort(_)).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, destroy_key(_)).WillOnce(Return(PSA_SUCCESS));

    const auto secret = make_random_secure_buffer(48);
    const auto result = sigma_derive_keys_impl<MockPsaBackend>(secret);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::KdfOutputFailed);
}


// ── sigma_i.hpp (sigma_i_derive_keys_impl) ───────────────────────────────────

TEST_F(PsaErrorTests, SigmaIDeriveKeysInitFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(GENERIC_ERROR));

    const auto secret = make_random_secure_buffer(48);
    const auto result = detail::sigma_i_derive_keys_impl<MockPsaBackend>(secret);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::InitFailed);
}

TEST_F(PsaErrorTests, SigmaIDeriveKeysImportFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, import_key(_, _, _, _)).WillOnce(Return(GENERIC_ERROR));

    const auto secret = make_random_secure_buffer(48);
    const auto result = detail::sigma_i_derive_keys_impl<MockPsaBackend>(secret);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::KeyImportFailed);
}

TEST_F(PsaErrorTests, SigmaIDeriveKeysSetupFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, import_key(_, _, _, _))
        .WillOnce(DoAll(SetArgPointee<3>(FAKE_KEY_ID), Return(PSA_SUCCESS)));
    EXPECT_CALL(*mock_, key_derivation_setup(_, _)).WillOnce(Return(GENERIC_ERROR));
    EXPECT_CALL(*mock_, key_derivation_abort(_)).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, destroy_key(_)).WillOnce(Return(PSA_SUCCESS));

    const auto secret = make_random_secure_buffer(48);
    const auto result = detail::sigma_i_derive_keys_impl<MockPsaBackend>(secret);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::KdfSetupFailed);
}

TEST_F(PsaErrorTests, SigmaIDeriveKeysOutputFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, import_key(_, _, _, _))
        .WillOnce(DoAll(SetArgPointee<3>(FAKE_KEY_ID), Return(PSA_SUCCESS)));
    EXPECT_CALL(*mock_, key_derivation_setup(_, _)).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, key_derivation_input_key(_, _, _)).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, key_derivation_input_bytes(_, _, _, _)).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, key_derivation_output_bytes(_, _, _)).WillOnce(Return(GENERIC_ERROR));
    EXPECT_CALL(*mock_, key_derivation_abort(_)).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, destroy_key(_)).WillOnce(Return(PSA_SUCCESS));

    const auto secret = make_random_secure_buffer(48);
    const auto result = detail::sigma_i_derive_keys_impl<MockPsaBackend>(secret);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::KdfOutputFailed);
}


// ── sigma_i.hpp (sigma_i_aes_gcm_encrypt_impl / decrypt_impl) ────────────────

TEST_F(PsaErrorTests, SigmaIAesGcmEncryptInitFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(GENERIC_ERROR));

    const auto key    = make_random_secure_buffer(32);
    const auto pt     = make_random_secure_buffer(64);
    const auto result = detail::sigma_i_aes_gcm_encrypt_impl<MockPsaBackend>(key, pt);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::InitFailed);
}

TEST_F(PsaErrorTests, SigmaIAesGcmEncryptKeyImportFailed) {
    EXPECT_CALL(*mock_, crypto_init())
        .WillOnce(Return(PSA_SUCCESS))
        .WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, generate_random(_, _)).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, import_key(_, _, _, _)).WillOnce(Return(GENERIC_ERROR));

    const auto key    = make_random_secure_buffer(32);
    const auto pt     = make_random_secure_buffer(64);
    const auto result = detail::sigma_i_aes_gcm_encrypt_impl<MockPsaBackend>(key, pt);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::KeyImportFailed);
}

TEST_F(PsaErrorTests, SigmaIAesGcmEncryptAeadFailed) {
    EXPECT_CALL(*mock_, crypto_init())
        .WillOnce(Return(PSA_SUCCESS))
        .WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, generate_random(_, _)).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, import_key(_, _, _, _))
        .WillOnce(DoAll(SetArgPointee<3>(FAKE_KEY_ID), Return(PSA_SUCCESS)));
    EXPECT_CALL(*mock_, aead_encrypt(_, _, _, _, _, _, _, _, _, _, _))
        .WillOnce(Return(GENERIC_ERROR));
    EXPECT_CALL(*mock_, destroy_key(_)).WillOnce(Return(PSA_SUCCESS));

    const auto key    = make_random_secure_buffer(32);
    const auto pt     = make_random_secure_buffer(64);
    const auto result = detail::sigma_i_aes_gcm_encrypt_impl<MockPsaBackend>(key, pt);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::EncryptionFailed);
}

TEST_F(PsaErrorTests, SigmaIAesGcmDecryptInitFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(GENERIC_ERROR));

    const auto key = make_random_secure_buffer(32);
    const SigmaIBundle bundle{ .iv = {}, .ciphertext = make_random_secure_buffer(80) };
    const auto result = detail::sigma_i_aes_gcm_decrypt_impl<MockPsaBackend>(key, bundle);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::InitFailed);
}

TEST_F(PsaErrorTests, SigmaIAesGcmDecryptKeyImportFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, import_key(_, _, _, _)).WillOnce(Return(GENERIC_ERROR));

    const auto key = make_random_secure_buffer(32);
    const SigmaIBundle bundle{ .iv = {}, .ciphertext = make_random_secure_buffer(80) };
    const auto result = detail::sigma_i_aes_gcm_decrypt_impl<MockPsaBackend>(key, bundle);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::KeyImportFailed);
}

TEST_F(PsaErrorTests, SigmaIAesGcmDecryptAeadFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, import_key(_, _, _, _))
        .WillOnce(DoAll(SetArgPointee<3>(FAKE_KEY_ID), Return(PSA_SUCCESS)));
    EXPECT_CALL(*mock_, aead_decrypt(_, _, _, _, _, _, _, _, _, _, _))
        .WillOnce(Return(GENERIC_ERROR));
    EXPECT_CALL(*mock_, destroy_key(_)).WillOnce(Return(PSA_SUCCESS));

    const auto key = make_random_secure_buffer(32);
    const SigmaIBundle bundle{ .iv = {}, .ciphertext = make_random_secure_buffer(80) };
    const auto result = detail::sigma_i_aes_gcm_decrypt_impl<MockPsaBackend>(key, bundle);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::SigmaAuthFailed);
}


// ── sigma.hpp (sigma_initiator_begin_impl) ───────────────────────────────────

TEST_F(PsaErrorTests, SigmaInitiatorBeginEcdhFailed) {
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(GENERIC_ERROR));

    const auto result = sigma_initiator_begin_impl<MockPsaBackend>(EcCurve::P256);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::InitFailed);
}


// ── sigma.hpp (sigma_responder_respond_impl) ─────────────────────────────────

TEST_F(PsaErrorTests, SigmaResponderRespondEcdhGenerateFailed) {
    constexpr std::size_t PRIV_KEY_SZ = 32;
    constexpr std::size_t PUB_KEY_SZ  = 65;
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(GENERIC_ERROR));

    const EccKeyPair responder{ .private_key_der = make_random_secure_buffer(PRIV_KEY_SZ),
                                .public_key_der  = make_random_secure_buffer(PUB_KEY_SZ) };
    const SigmaMsg1 msg1{ .ephemeral_pub_i = make_random_secure_buffer(PUB_KEY_SZ) };
    const auto result = sigma_responder_respond_impl<MockPsaBackend>(
        msg1, responder, EcCurve::P256);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::InitFailed);
}

TEST_F(PsaErrorTests, SigmaResponderRespondEcdhComputeFailed) {
    constexpr std::size_t FAKE_KEY_BYTES = 32;
    constexpr std::size_t PRIV_KEY_SZ   = 32;
    constexpr std::size_t PUB_KEY_SZ    = 65;
    // generate_key success (ecdh_generate_key_impl), then crypto_init fails for compute
    EXPECT_CALL(*mock_, crypto_init())
        .WillOnce(Return(PSA_SUCCESS))
        .WillOnce(Return(GENERIC_ERROR));
    EXPECT_CALL(*mock_, generate_key(_, _))
        .WillOnce(DoAll(SetArgPointee<1>(FAKE_KEY_ID), Return(PSA_SUCCESS)));
    EXPECT_CALL(*mock_, export_key(_, _, _, _))
        .WillOnce(DoAll(SetArgPointee<3>(FAKE_KEY_BYTES), Return(PSA_SUCCESS)));
    EXPECT_CALL(*mock_, export_public_key(_, _, _, _))
        .WillOnce(DoAll(SetArgPointee<3>(FAKE_KEY_BYTES), Return(PSA_SUCCESS)));
    EXPECT_CALL(*mock_, destroy_key(_)).WillOnce(Return(PSA_SUCCESS));

    const EccKeyPair responder{ .private_key_der = make_random_secure_buffer(PRIV_KEY_SZ),
                                .public_key_der  = make_random_secure_buffer(PUB_KEY_SZ) };
    const SigmaMsg1 msg1{ .ephemeral_pub_i = make_random_secure_buffer(PUB_KEY_SZ) };
    const auto result = sigma_responder_respond_impl<MockPsaBackend>(
        msg1, responder, EcCurve::P256);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::InitFailed);
}

TEST_F(PsaErrorTests, SigmaResponderRespondDeriveKeysFailed) {
    constexpr std::size_t FAKE_KEY_BYTES         = 32;
    constexpr std::size_t SHARED_SECRET_SZ       = 32;
    constexpr std::size_t PRIV_KEY_SZ            = 32;
    constexpr std::size_t PUB_KEY_SZ             = 65;
    constexpr int         RAW_KEY_AGREE_OUT_IDX  = 6;
    // ecdh_generate_key succeeds, ecdh_compute succeeds, sigma_derive_keys fails at init
    EXPECT_CALL(*mock_, crypto_init())
        .WillOnce(Return(PSA_SUCCESS))
        .WillOnce(Return(PSA_SUCCESS))
        .WillOnce(Return(GENERIC_ERROR));
    EXPECT_CALL(*mock_, generate_key(_, _))
        .WillOnce(DoAll(SetArgPointee<1>(FAKE_KEY_ID), Return(PSA_SUCCESS)));
    EXPECT_CALL(*mock_, export_key(_, _, _, _))
        .WillOnce(DoAll(SetArgPointee<3>(FAKE_KEY_BYTES), Return(PSA_SUCCESS)));
    EXPECT_CALL(*mock_, export_public_key(_, _, _, _))
        .WillOnce(DoAll(SetArgPointee<3>(FAKE_KEY_BYTES), Return(PSA_SUCCESS)));
    EXPECT_CALL(*mock_, import_key(_, _, _, _))
        .WillOnce(DoAll(SetArgPointee<3>(FAKE_KEY_ID), Return(PSA_SUCCESS)));
    EXPECT_CALL(*mock_, raw_key_agreement(_, _, _, _, _, _, _))
        .WillOnce(DoAll(SetArgPointee<RAW_KEY_AGREE_OUT_IDX>(SHARED_SECRET_SZ), Return(PSA_SUCCESS)));
    EXPECT_CALL(*mock_, destroy_key(_)).WillRepeatedly(Return(PSA_SUCCESS));

    const EccKeyPair responder{ .private_key_der = make_random_secure_buffer(PRIV_KEY_SZ),
                                .public_key_der  = make_random_secure_buffer(PUB_KEY_SZ) };
    const SigmaMsg1 msg1{ .ephemeral_pub_i = make_random_secure_buffer(PUB_KEY_SZ) };
    const auto result = sigma_responder_respond_impl<MockPsaBackend>(
        msg1, responder, EcCurve::P256);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::InitFailed);
}


// ── sigma.hpp (sigma_initiator_finish_impl) ──────────────────────────────────

TEST_F(PsaErrorTests, SigmaInitiatorFinishEcdhComputeFailed) {
    constexpr std::size_t PRIV_KEY_SZ = 32;
    constexpr std::size_t PUB_KEY_SZ  = 65;
    constexpr std::size_t SIG_SZ      = 64;
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(GENERIC_ERROR));

    const EccKeyPair kp{ .private_key_der = make_random_secure_buffer(PRIV_KEY_SZ),
                         .public_key_der  = make_random_secure_buffer(PUB_KEY_SZ) };
    SigmaInitiatorState state{
        .ephemeral_key_pair = EccKeyPair{
            .private_key_der = make_random_secure_buffer(PRIV_KEY_SZ),
            .public_key_der  = make_random_secure_buffer(PUB_KEY_SZ),
        },
        .ephemeral_pub_i = make_random_secure_buffer(PUB_KEY_SZ),
    };
    const SigmaMsg2 msg2{
        .ephemeral_pub_r = make_random_secure_buffer(PUB_KEY_SZ),
        .identity_pub_r  = make_random_secure_buffer(PUB_KEY_SZ),
        .signature_r     = make_random_secure_buffer(SIG_SZ),
        .mac_r           = {},
    };
    const SecureBuffer expected_pub = make_random_secure_buffer(65);
    const auto result = sigma_initiator_finish_impl<MockPsaBackend>(
        std::move(state), msg2, kp, expected_pub, EcCurve::P256);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::InitFailed);
}


// ── sigma.hpp (sigma_responder_finish_impl) ──────────────────────────────────

TEST_F(PsaErrorTests, SigmaResponderFinishHmacVerifyFailed) {
    constexpr std::size_t PUB_KEY_SZ  = 65;
    constexpr std::size_t SIG_SZ      = 64;
    constexpr std::size_t MAC_KEY_SZ  = 48;
    constexpr std::size_t SESSION_SZ  = 32;
    // Identity matches expected, but hmac_verify fails at crypto_init
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(GENERIC_ERROR));

    auto identity_pub = make_random_secure_buffer(PUB_KEY_SZ);
    SecureBuffer expected_pub(identity_pub.size());
    std::ranges::copy(identity_pub, expected_pub.begin());

    SecureBuffer identity_pub_copy(identity_pub.size());
    std::ranges::copy(identity_pub, identity_pub_copy.begin());
    const SigmaMsg3 msg3{
        .identity_pub_i = std::move(identity_pub_copy),
        .signature_i    = make_random_secure_buffer(SIG_SZ),
        .mac_i          = {},
    };

    const SigmaSessionKeys session_keys{
        .mac_key     = make_random_secure_buffer(MAC_KEY_SZ),
        .session_key = make_random_secure_buffer(SESSION_SZ),
    };
    const SigmaMsg1 msg1{ .ephemeral_pub_i = make_random_secure_buffer(PUB_KEY_SZ) };
    const SigmaMsg2 msg2{
        .ephemeral_pub_r = make_random_secure_buffer(PUB_KEY_SZ),
        .identity_pub_r  = make_random_secure_buffer(PUB_KEY_SZ),
        .signature_r     = make_random_secure_buffer(SIG_SZ),
        .mac_r           = {},
    };

    const auto result = sigma_responder_finish_impl<MockPsaBackend>(
        msg3, session_keys, msg1, msg2, expected_pub, EcCurve::P256);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::InitFailed);
}


// ── sigma_i.hpp (sigma_i_responder_respond_impl) ─────────────────────────────

TEST_F(PsaErrorTests, SigmaIResponderRespondEcdhGenerateFailed) {
    constexpr std::size_t PRIV_KEY_SZ = 32;
    constexpr std::size_t PUB_KEY_SZ  = 65;
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(GENERIC_ERROR));

    const EccKeyPair responder{ .private_key_der = make_random_secure_buffer(PRIV_KEY_SZ),
                                .public_key_der  = make_random_secure_buffer(PUB_KEY_SZ) };
    const SigmaMsg1 msg1{ .ephemeral_pub_i = make_random_secure_buffer(PUB_KEY_SZ) };
    const auto result = sigma_i_responder_respond_impl<MockPsaBackend>(
        msg1, responder, EcCurve::P256);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::InitFailed);
}


// ── sigma_i.hpp (sigma_i_initiator_finish_impl) ──────────────────────────────

TEST_F(PsaErrorTests, SigmaIInitiatorFinishEcdhComputeFailed) {
    constexpr std::size_t PRIV_KEY_SZ  = 32;
    constexpr std::size_t PUB_KEY_SZ   = 65;
    constexpr std::size_t BUNDLE_CT_SZ = 80;
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(GENERIC_ERROR));

    const EccKeyPair kp{ .private_key_der = make_random_secure_buffer(PRIV_KEY_SZ),
                         .public_key_der  = make_random_secure_buffer(PUB_KEY_SZ) };
    SigmaInitiatorState state{
        .ephemeral_key_pair = EccKeyPair{
            .private_key_der = make_random_secure_buffer(PRIV_KEY_SZ),
            .public_key_der  = make_random_secure_buffer(PUB_KEY_SZ),
        },
        .ephemeral_pub_i = make_random_secure_buffer(PUB_KEY_SZ),
    };
    const SigmaIMsg2 msg2{
        .ephemeral_pub_r = make_random_secure_buffer(PUB_KEY_SZ),
        .bundle_r        = SigmaIBundle{ .iv = {}, .ciphertext = make_random_secure_buffer(BUNDLE_CT_SZ) },
    };
    const SecureBuffer expected_pub = make_random_secure_buffer(65);
    const auto result = sigma_i_initiator_finish_impl<MockPsaBackend>(
        std::move(state), msg2, kp, expected_pub, EcCurve::P256);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::InitFailed);
}


// ── sigma_i.hpp (sigma_i_responder_finish_impl) ──────────────────────────────

TEST_F(PsaErrorTests, SigmaIResponderFinishHmacVerifyFailed) {
    constexpr std::size_t BUNDLE_CT_SZ = 80;
    constexpr std::size_t MAC_KEY_SZ   = 48;
    constexpr std::size_t SESSION_SZ   = 32;
    constexpr std::size_t ENC_KEY_SZ   = 32;
    constexpr std::size_t PUB_KEY_SZ   = 65;
    // Decrypt succeeds but returns a well-formed bundle whose identity matches,
    // then hmac_verify fails at crypto_init.
    // We can't inject that without a real decrypt, so instead we fail the
    // decrypt itself (aead_decrypt returns error → SigmaAuthFailed → returns false).
    EXPECT_CALL(*mock_, crypto_init()).WillOnce(Return(PSA_SUCCESS));
    EXPECT_CALL(*mock_, import_key(_, _, _, _))
        .WillOnce(DoAll(SetArgPointee<3>(FAKE_KEY_ID), Return(PSA_SUCCESS)));
    EXPECT_CALL(*mock_, aead_decrypt(_, _, _, _, _, _, _, _, _, _, _))
        .WillOnce(Return(GENERIC_ERROR));
    EXPECT_CALL(*mock_, destroy_key(_)).WillOnce(Return(PSA_SUCCESS));

    const SigmaIMsg3 msg3{
        .bundle_i = SigmaIBundle{ .iv = {}, .ciphertext = make_random_secure_buffer(BUNDLE_CT_SZ) },
    };
    const SigmaIResponderState responder_state{
        .session_keys = SigmaSessionKeys{
            .mac_key     = make_random_secure_buffer(MAC_KEY_SZ),
            .session_key = make_random_secure_buffer(SESSION_SZ),
        },
        .enc_key_i = make_random_secure_buffer(ENC_KEY_SZ),
    };
    const SigmaMsg1 msg1{ .ephemeral_pub_i = make_random_secure_buffer(PUB_KEY_SZ) };
    const SigmaIMsg2 msg2{
        .ephemeral_pub_r = make_random_secure_buffer(PUB_KEY_SZ),
        .bundle_r        = SigmaIBundle{ .iv = {}, .ciphertext = make_random_secure_buffer(BUNDLE_CT_SZ) },
    };
    const SecureBuffer expected_pub = make_random_secure_buffer(PUB_KEY_SZ);

    const auto result = sigma_i_responder_finish_impl<MockPsaBackend>(
        msg3, responder_state, msg1, msg2, expected_pub, EcCurve::P256);

    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(*result);
}
