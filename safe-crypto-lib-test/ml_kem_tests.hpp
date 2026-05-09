// SPDX-License-Identifier: Apache-2.0

#pragma once

// ML-KEM (FIPS 203) tests.
// Active for SAFE_CRYPTO_PROVIDER_OPENSSL and SAFE_CRYPTO_PQC_LIBOQS builds.

#include <cstddef>
#include <cstring>

#include <gtest/gtest.h>

#if defined(SAFE_CRYPTO_PROVIDER_OPENSSL)
#include "ml_kem_variant.hpp"
#include "openssl_backend.hpp"
#include "pqc_kem.hpp"
#include "test_utils.hpp"
using MlKemBackend = OpenSslBackend;
#elif defined(SAFE_CRYPTO_PQC_LIBOQS) && defined(SAFE_CRYPTO_ARM_ASM_AVAILABLE)
#include "arm_asm_backend.hpp"
#include "ml_kem_variant.hpp"
#include "pqc_kem.hpp"
#include "test_utils.hpp"
using MlKemBackend = ArmAsmBackend;
#elif defined(SAFE_CRYPTO_PQC_LIBOQS)
#include "ml_kem_variant.hpp"
#include "pqc_kem.hpp"
#include "psa_mbedtls_backend.hpp"
#include "test_utils.hpp"
using MlKemBackend = RealPsaBackend;
#endif

#if defined(SAFE_CRYPTO_PROVIDER_OPENSSL) || defined(SAFE_CRYPTO_PQC_LIBOQS)

class MlKemTests : public ::testing::Test {};

// Copy bytes from a SecureBuffer into a fresh SecureBuffer (for test purposes only).
static SecureBuffer copy_secure_buffer_kem(const SecureBuffer& src) {
    SecureBuffer dst(src.size());
    std::memcpy(dst.data(), src.data(), src.size());
    return dst;
}


// --- ML-KEM-512 ---

TEST_F(MlKemTests, Kem512_KeygenProducesCorrectSizes) {
    const auto kp = ml_kem_generate_key_impl<MlKemVariant::Kem512, MlKemBackend>();
    ASSERT_TRUE(kp.has_value());
    EXPECT_EQ(kp->private_key.size(), ml_kem_private_key_size(MlKemVariant::Kem512));
    EXPECT_EQ(kp->public_key.size(),  ml_kem_public_key_size(MlKemVariant::Kem512));
}

TEST_F(MlKemTests, Kem512_EncapDecapRoundTrip) {
    auto kp = ml_kem_generate_key_impl<MlKemVariant::Kem512, MlKemBackend>();
    ASSERT_TRUE(kp.has_value());

    const MlKemPublicKey<MlKemVariant::Kem512> pub{
        .public_key = std::move(kp->public_key)
    };
    const auto encap = ml_kem_encapsulate_impl<MlKemVariant::Kem512, MlKemBackend>(pub);
    ASSERT_TRUE(encap.has_value());
    EXPECT_EQ(encap->ciphertext.size(),    ml_kem_ciphertext_size(MlKemVariant::Kem512));
    EXPECT_EQ(encap->shared_secret.size(), ml_kem_shared_secret_size(MlKemVariant::Kem512));

    const auto decap = ml_kem_decapsulate_impl<MlKemVariant::Kem512, MlKemBackend>(kp.value(), encap->ciphertext);
    ASSERT_TRUE(decap.has_value());
    EXPECT_EQ(decap->size(), ml_kem_shared_secret_size(MlKemVariant::Kem512));

    // Both parties must derive the same shared secret.
    ASSERT_EQ(encap->shared_secret.size(), decap->size());
    EXPECT_EQ(std::memcmp(encap->shared_secret.data(), decap->data(), decap->size()), 0);
}

TEST_F(MlKemTests, Kem512_DecapRejectsTamperedCiphertext) {
    auto kp = ml_kem_generate_key_impl<MlKemVariant::Kem512, MlKemBackend>();
    ASSERT_TRUE(kp.has_value());

    const MlKemPublicKey<MlKemVariant::Kem512> pub{
        .public_key = copy_secure_buffer_kem(kp->public_key)
    };
    const auto encap = ml_kem_encapsulate_impl<MlKemVariant::Kem512, MlKemBackend>(pub);
    ASSERT_TRUE(encap.has_value());

    // Tamper the ciphertext: decap must still return (implicitly rejecting) per FIPS 203
    // implicit rejection — the decapsulated shared secret will differ from the encap one.
    SecureBuffer tampered_ct = copy_secure_buffer_kem(encap->ciphertext);
    tampered_ct[tampered_ct.size() / 2] ^= 0xFFU;

    const auto decap = ml_kem_decapsulate_impl<MlKemVariant::Kem512, MlKemBackend>(kp.value(), tampered_ct);
    // ML-KEM uses implicit rejection: decap always succeeds but yields a different secret.
    ASSERT_TRUE(decap.has_value());
    ASSERT_EQ(encap->shared_secret.size(), decap->size());
    EXPECT_NE(std::memcmp(encap->shared_secret.data(), decap->data(), decap->size()), 0);
}

TEST_F(MlKemTests, Kem512_ExportImportRoundTrip) {
    auto kp = ml_kem_generate_key_impl<MlKemVariant::Kem512, MlKemBackend>();
    ASSERT_TRUE(kp.has_value());

    // Re-import the exported key bytes and verify encap/decap still works.
    SecureBuffer priv_copy = copy_secure_buffer_kem(kp->private_key);
    SecureBuffer pub_copy  = copy_secure_buffer_kem(kp->public_key);

    const MlKemKeyPair<MlKemVariant::Kem512> kp2{
        .private_key = std::move(priv_copy),
        .public_key  = copy_secure_buffer_kem(kp->public_key),
    };
    const MlKemPublicKey<MlKemVariant::Kem512> pub{ .public_key = std::move(pub_copy) };

    const auto encap = ml_kem_encapsulate_impl<MlKemVariant::Kem512, MlKemBackend>(pub);
    ASSERT_TRUE(encap.has_value());

    const auto decap = ml_kem_decapsulate_impl<MlKemVariant::Kem512, MlKemBackend>(kp2, encap->ciphertext);
    ASSERT_TRUE(decap.has_value());
    ASSERT_EQ(encap->shared_secret.size(), decap->size());
    EXPECT_EQ(std::memcmp(encap->shared_secret.data(), decap->data(), decap->size()), 0);
}


TEST_F(MlKemTests, Kem512_EncapRejectsPublicKeyWithTrailingByte) {
    auto kp = ml_kem_generate_key_impl<MlKemVariant::Kem512, MlKemBackend>();
    ASSERT_TRUE(kp.has_value());

    // Append one extra byte to the public key.
    SecureBuffer oversized(kp->public_key.size() + 1);
    std::memcpy(oversized.data(), kp->public_key.data(), kp->public_key.size());
    oversized[oversized.size() - 1] = 0x00U;

    const MlKemPublicKey<MlKemVariant::Kem512> bad_pub{ .public_key = std::move(oversized) };
    const auto result = ml_kem_encapsulate_impl<MlKemVariant::Kem512, MlKemBackend>(bad_pub);
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::InvalidArgument);
}

TEST_F(MlKemTests, Kem512_DecapRejectsCiphertextWithTrailingByte) {
    auto kp = ml_kem_generate_key_impl<MlKemVariant::Kem512, MlKemBackend>();
    ASSERT_TRUE(kp.has_value());

    const MlKemPublicKey<MlKemVariant::Kem512> pub{
        .public_key = copy_secure_buffer_kem(kp->public_key)
    };
    const auto encap = ml_kem_encapsulate_impl<MlKemVariant::Kem512, MlKemBackend>(pub);
    ASSERT_TRUE(encap.has_value());

    // Append one extra byte to the ciphertext.
    SecureBuffer oversized(encap->ciphertext.size() + 1);
    std::memcpy(oversized.data(), encap->ciphertext.data(), encap->ciphertext.size());
    oversized[oversized.size() - 1] = 0x00U;

    const auto result = ml_kem_decapsulate_impl<MlKemVariant::Kem512, MlKemBackend>(kp.value(), oversized);
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::InvalidArgument);
}

TEST_F(MlKemTests, Kem512_DecapRejectsPrivateKeyWithTrailingByte) {
    auto kp = ml_kem_generate_key_impl<MlKemVariant::Kem512, MlKemBackend>();
    ASSERT_TRUE(kp.has_value());

    const MlKemPublicKey<MlKemVariant::Kem512> pub{
        .public_key = copy_secure_buffer_kem(kp->public_key)
    };
    const auto encap = ml_kem_encapsulate_impl<MlKemVariant::Kem512, MlKemBackend>(pub);
    ASSERT_TRUE(encap.has_value());

    // Append one extra byte to the private key.
    SecureBuffer oversized_priv(kp->private_key.size() + 1);
    std::memcpy(oversized_priv.data(), kp->private_key.data(), kp->private_key.size());
    oversized_priv[oversized_priv.size() - 1] = 0x00U;

    const MlKemKeyPair<MlKemVariant::Kem512> bad_kp{
        .private_key = std::move(oversized_priv),
        .public_key  = copy_secure_buffer_kem(kp->public_key),
    };
    const auto result = ml_kem_decapsulate_impl<MlKemVariant::Kem512, MlKemBackend>(bad_kp, encap->ciphertext);
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::InvalidArgument);
}


// --- ML-KEM-768 ---

TEST_F(MlKemTests, Kem768_EncapDecapRoundTrip) {
    auto kp = ml_kem_generate_key_impl<MlKemVariant::Kem768, MlKemBackend>();
    ASSERT_TRUE(kp.has_value());
    EXPECT_EQ(kp->private_key.size(), ml_kem_private_key_size(MlKemVariant::Kem768));
    EXPECT_EQ(kp->public_key.size(),  ml_kem_public_key_size(MlKemVariant::Kem768));

    const MlKemPublicKey<MlKemVariant::Kem768> pub{ .public_key = std::move(kp->public_key) };
    const auto encap = ml_kem_encapsulate_impl<MlKemVariant::Kem768, MlKemBackend>(pub);
    ASSERT_TRUE(encap.has_value());
    EXPECT_EQ(encap->ciphertext.size(), ml_kem_ciphertext_size(MlKemVariant::Kem768));

    const auto decap = ml_kem_decapsulate_impl<MlKemVariant::Kem768, MlKemBackend>(kp.value(), encap->ciphertext);
    ASSERT_TRUE(decap.has_value());
    ASSERT_EQ(encap->shared_secret.size(), decap->size());
    EXPECT_EQ(std::memcmp(encap->shared_secret.data(), decap->data(), decap->size()), 0);
}


// --- ML-KEM-1024 ---

TEST_F(MlKemTests, Kem1024_EncapDecapRoundTrip) {
    auto kp = ml_kem_generate_key_impl<MlKemVariant::Kem1024, MlKemBackend>();
    ASSERT_TRUE(kp.has_value());
    EXPECT_EQ(kp->private_key.size(), ml_kem_private_key_size(MlKemVariant::Kem1024));
    EXPECT_EQ(kp->public_key.size(),  ml_kem_public_key_size(MlKemVariant::Kem1024));

    const MlKemPublicKey<MlKemVariant::Kem1024> pub{ .public_key = std::move(kp->public_key) };
    const auto encap = ml_kem_encapsulate_impl<MlKemVariant::Kem1024, MlKemBackend>(pub);
    ASSERT_TRUE(encap.has_value());
    EXPECT_EQ(encap->ciphertext.size(), ml_kem_ciphertext_size(MlKemVariant::Kem1024));

    const auto decap = ml_kem_decapsulate_impl<MlKemVariant::Kem1024, MlKemBackend>(kp.value(), encap->ciphertext);
    ASSERT_TRUE(decap.has_value());
    ASSERT_EQ(encap->shared_secret.size(), decap->size());
    EXPECT_EQ(std::memcmp(encap->shared_secret.data(), decap->data(), decap->size()), 0);
}

// --- Variant mismatch rejection ---

TEST_F(MlKemTests, Kem512_EncapRejectsAlgorithmVariantMismatch) {
    // Generate a Kem512 key pair, then try to encapsulate using the Kem768 algorithm ID.
    auto kp = ml_kem_generate_key_impl<MlKemVariant::Kem512, MlKemBackend>();
    ASSERT_TRUE(kp.has_value());

    auto attrs = MlKemBackend::make_ml_kem_encap_attrs(MlKemVariant::Kem512);
    auto raw_id = MlKemBackend::null_key_id();
    ASSERT_EQ(MlKemBackend::import_key(&attrs,
                                        kp->public_key.data(), kp->public_key.size(),
                                        &raw_id), MlKemBackend::ok);

    constexpr std::size_t ct_size = ml_kem_ciphertext_size(MlKemVariant::Kem768);
    constexpr std::size_t ss_size = ml_kem_shared_secret_size(MlKemVariant::Kem768);
    SecureBuffer ct(ct_size);
    SecureBuffer ss(ss_size);
    std::size_t ct_len = 0;
    std::size_t ss_len = 0;

    // Pass the Kem768 algorithm ID but the key was imported as Kem512 — must fail.
    const auto status = MlKemBackend::kem_encapsulate(
        raw_id, MlKemBackend::alg_ml_kem(MlKemVariant::Kem768),
        ct.data(), ct_size, &ct_len,
        ss.data(), ss_size, &ss_len);
    EXPECT_NE(status, MlKemBackend::ok);

    EXPECT_EQ(MlKemBackend::destroy_key(raw_id), MlKemBackend::ok);
}

TEST_F(MlKemTests, Kem512_DecapRejectsAlgorithmVariantMismatch) {
    // Generate a Kem512 key pair, then try to decapsulate using the Kem768 algorithm ID.
    auto kp = ml_kem_generate_key_impl<MlKemVariant::Kem512, MlKemBackend>();
    ASSERT_TRUE(kp.has_value());

    const MlKemPublicKey<MlKemVariant::Kem512> pub{ .public_key = copy_secure_buffer_kem(kp->public_key) };
    const auto encap = ml_kem_encapsulate_impl<MlKemVariant::Kem512, MlKemBackend>(pub);
    ASSERT_TRUE(encap.has_value());

    auto attrs = MlKemBackend::make_ml_kem_decap_attrs(MlKemVariant::Kem512);
    auto raw_id = MlKemBackend::null_key_id();
    ASSERT_EQ(MlKemBackend::import_key(&attrs,
                                        kp->private_key.data(), kp->private_key.size(),
                                        &raw_id), MlKemBackend::ok);

    constexpr std::size_t ss_size = ml_kem_shared_secret_size(MlKemVariant::Kem768);
    SecureBuffer ss(ss_size);
    std::size_t ss_len = 0;

    // Pass the Kem768 algorithm ID but the key was imported as Kem512 — must fail.
    const auto status = MlKemBackend::kem_decapsulate(
        raw_id, MlKemBackend::alg_ml_kem(MlKemVariant::Kem768),
        encap->ciphertext.data(), encap->ciphertext.size(),
        ss.data(), ss_size, &ss_len);
    EXPECT_NE(status, MlKemBackend::ok);

    EXPECT_EQ(MlKemBackend::destroy_key(raw_id), MlKemBackend::ok);
}

#endif  // SAFE_CRYPTO_PROVIDER_OPENSSL || SAFE_CRYPTO_PQC_LIBOQS
