/*
Copyright Permanence AI, 2026. All rights reserved.

*/

#pragma once

// ML-KEM (FIPS 203) tests — OpenSSL provider only.
// Compiled into every build but the inner tests are guarded by
// SAFE_CRYPTO_PROVIDER_OPENSSL so they only run when that backend is active.

#include <cstddef>
#include <cstring>

#include <gtest/gtest.h>

#ifdef SAFE_CRYPTO_PROVIDER_OPENSSL

#include "ml_kem_variant.hpp"
#include "openssl_backend.hpp"
#include "pqc_kem.hpp"
#include "test_utils.hpp"


class MlKemTests : public ::testing::Test {};

// Copy bytes from a SecureBuffer into a fresh SecureBuffer (for test purposes only).
static SecureBuffer copy_secure_buffer_kem(const SecureBuffer& src) {
    SecureBuffer dst(src.size());
    std::memcpy(dst.data(), src.data(), src.size());
    return dst;
}


// --- ML-KEM-512 ---

TEST_F(MlKemTests, Kem512_KeygenProducesCorrectSizes) {
    const auto kp = ml_kem_generate_key_impl<MlKemVariant::Kem512, OpenSslBackend>();
    ASSERT_TRUE(kp.has_value());
    EXPECT_EQ(kp->private_key.size(), ml_kem_private_key_size(MlKemVariant::Kem512));
    EXPECT_EQ(kp->public_key.size(),  ml_kem_public_key_size(MlKemVariant::Kem512));
}

TEST_F(MlKemTests, Kem512_EncapDecapRoundTrip) {
    auto kp = ml_kem_generate_key_impl<MlKemVariant::Kem512, OpenSslBackend>();
    ASSERT_TRUE(kp.has_value());

    const MlKemPublicKey<MlKemVariant::Kem512> pub{
        .public_key = std::move(kp->public_key)
    };
    const auto encap = ml_kem_encapsulate_impl<MlKemVariant::Kem512, OpenSslBackend>(pub);
    ASSERT_TRUE(encap.has_value());
    EXPECT_EQ(encap->ciphertext.size(),    ml_kem_ciphertext_size(MlKemVariant::Kem512));
    EXPECT_EQ(encap->shared_secret.size(), ml_kem_shared_secret_size(MlKemVariant::Kem512));

    const auto decap = ml_kem_decapsulate_impl<MlKemVariant::Kem512, OpenSslBackend>(kp.value(), encap->ciphertext);
    ASSERT_TRUE(decap.has_value());
    EXPECT_EQ(decap->size(), ml_kem_shared_secret_size(MlKemVariant::Kem512));

    // Both parties must derive the same shared secret.
    ASSERT_EQ(encap->shared_secret.size(), decap->size());
    EXPECT_EQ(std::memcmp(encap->shared_secret.data(), decap->data(), decap->size()), 0);
}

TEST_F(MlKemTests, Kem512_DecapRejectsTamperedCiphertext) {
    auto kp = ml_kem_generate_key_impl<MlKemVariant::Kem512, OpenSslBackend>();
    ASSERT_TRUE(kp.has_value());

    const MlKemPublicKey<MlKemVariant::Kem512> pub{
        .public_key = copy_secure_buffer_kem(kp->public_key)
    };
    const auto encap = ml_kem_encapsulate_impl<MlKemVariant::Kem512, OpenSslBackend>(pub);
    ASSERT_TRUE(encap.has_value());

    // Tamper the ciphertext: decap must still return (implicitly rejecting) per FIPS 203
    // implicit rejection — the decapsulated shared secret will differ from the encap one.
    SecureBuffer tampered_ct = copy_secure_buffer_kem(encap->ciphertext);
    tampered_ct[tampered_ct.size() / 2] ^= 0xFFU;

    const auto decap = ml_kem_decapsulate_impl<MlKemVariant::Kem512, OpenSslBackend>(kp.value(), tampered_ct);
    // ML-KEM uses implicit rejection: decap always succeeds but yields a different secret.
    ASSERT_TRUE(decap.has_value());
    ASSERT_EQ(encap->shared_secret.size(), decap->size());
    EXPECT_NE(std::memcmp(encap->shared_secret.data(), decap->data(), decap->size()), 0);
}

TEST_F(MlKemTests, Kem512_ExportImportRoundTrip) {
    auto kp = ml_kem_generate_key_impl<MlKemVariant::Kem512, OpenSslBackend>();
    ASSERT_TRUE(kp.has_value());

    // Re-import the exported key bytes and verify encap/decap still works.
    SecureBuffer priv_copy = copy_secure_buffer_kem(kp->private_key);
    SecureBuffer pub_copy  = copy_secure_buffer_kem(kp->public_key);

    const MlKemKeyPair<MlKemVariant::Kem512> kp2{
        .private_key = std::move(priv_copy),
        .public_key  = copy_secure_buffer_kem(kp->public_key),
    };
    const MlKemPublicKey<MlKemVariant::Kem512> pub{ .public_key = std::move(pub_copy) };

    const auto encap = ml_kem_encapsulate_impl<MlKemVariant::Kem512, OpenSslBackend>(pub);
    ASSERT_TRUE(encap.has_value());

    const auto decap = ml_kem_decapsulate_impl<MlKemVariant::Kem512, OpenSslBackend>(kp2, encap->ciphertext);
    ASSERT_TRUE(decap.has_value());
    ASSERT_EQ(encap->shared_secret.size(), decap->size());
    EXPECT_EQ(std::memcmp(encap->shared_secret.data(), decap->data(), decap->size()), 0);
}


// --- ML-KEM-768 ---

TEST_F(MlKemTests, Kem768_EncapDecapRoundTrip) {
    auto kp = ml_kem_generate_key_impl<MlKemVariant::Kem768, OpenSslBackend>();
    ASSERT_TRUE(kp.has_value());
    EXPECT_EQ(kp->private_key.size(), ml_kem_private_key_size(MlKemVariant::Kem768));
    EXPECT_EQ(kp->public_key.size(),  ml_kem_public_key_size(MlKemVariant::Kem768));

    const MlKemPublicKey<MlKemVariant::Kem768> pub{ .public_key = std::move(kp->public_key) };
    const auto encap = ml_kem_encapsulate_impl<MlKemVariant::Kem768, OpenSslBackend>(pub);
    ASSERT_TRUE(encap.has_value());
    EXPECT_EQ(encap->ciphertext.size(), ml_kem_ciphertext_size(MlKemVariant::Kem768));

    const auto decap = ml_kem_decapsulate_impl<MlKemVariant::Kem768, OpenSslBackend>(kp.value(), encap->ciphertext);
    ASSERT_TRUE(decap.has_value());
    ASSERT_EQ(encap->shared_secret.size(), decap->size());
    EXPECT_EQ(std::memcmp(encap->shared_secret.data(), decap->data(), decap->size()), 0);
}


// --- ML-KEM-1024 ---

TEST_F(MlKemTests, Kem1024_EncapDecapRoundTrip) {
    auto kp = ml_kem_generate_key_impl<MlKemVariant::Kem1024, OpenSslBackend>();
    ASSERT_TRUE(kp.has_value());
    EXPECT_EQ(kp->private_key.size(), ml_kem_private_key_size(MlKemVariant::Kem1024));
    EXPECT_EQ(kp->public_key.size(),  ml_kem_public_key_size(MlKemVariant::Kem1024));

    const MlKemPublicKey<MlKemVariant::Kem1024> pub{ .public_key = std::move(kp->public_key) };
    const auto encap = ml_kem_encapsulate_impl<MlKemVariant::Kem1024, OpenSslBackend>(pub);
    ASSERT_TRUE(encap.has_value());
    EXPECT_EQ(encap->ciphertext.size(), ml_kem_ciphertext_size(MlKemVariant::Kem1024));

    const auto decap = ml_kem_decapsulate_impl<MlKemVariant::Kem1024, OpenSslBackend>(kp.value(), encap->ciphertext);
    ASSERT_TRUE(decap.has_value());
    ASSERT_EQ(encap->shared_secret.size(), decap->size());
    EXPECT_EQ(std::memcmp(encap->shared_secret.data(), decap->data(), decap->size()), 0);
}

#endif  // SAFE_CRYPTO_PROVIDER_OPENSSL
