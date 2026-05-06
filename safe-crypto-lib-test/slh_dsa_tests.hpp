// SPDX-License-Identifier: Apache-2.0

#pragma once

// SLH-DSA (FIPS 205) tests — OpenSSL provider only.
// Compiled into every build but the inner tests are guarded by
// SAFE_CRYPTO_PROVIDER_OPENSSL so they only run when that backend is active.

#include <cstddef>
#include <cstring>

#include <gtest/gtest.h>

#ifdef SAFE_CRYPTO_PROVIDER_OPENSSL

#include "openssl_backend.hpp"
#include "pqc_dsa.hpp"
#include "test_utils.hpp"


class SlhDsaTests : public ::testing::Test {
protected:
    static constexpr std::size_t kMessageSize = 64;
};

// Copy bytes from a SecureBuffer into a fresh SecureBuffer (for test purposes only).
static SecureBuffer copy_secure_buffer(const SecureBuffer& src) {
    SecureBuffer dst(src.size());
    std::memcpy(dst.data(), src.data(), src.size());
    return dst;
}


// --- SHA2-128s ---

TEST_F(SlhDsaTests, Sha2_128s_KeygenProducesCorrectSizes) {
    const auto kp = slh_dsa_generate_key_impl<SlhDsaVariant::Sha2_128s, OpenSslBackend>();
    ASSERT_TRUE(kp.has_value());
    EXPECT_EQ(kp->private_key.size(), slh_dsa_private_key_size(SlhDsaVariant::Sha2_128s));
    EXPECT_EQ(kp->public_key.size(),  slh_dsa_public_key_size(SlhDsaVariant::Sha2_128s));
}

TEST_F(SlhDsaTests, Sha2_128s_SignVerifyRoundTrip) {
    auto kp = slh_dsa_generate_key_impl<SlhDsaVariant::Sha2_128s, OpenSslBackend>();
    ASSERT_TRUE(kp.has_value());

    const auto msg = make_random_secure_buffer(kMessageSize);
    const auto sig = slh_dsa_sign_impl<SlhDsaVariant::Sha2_128s, OpenSslBackend>(*kp, msg);
    ASSERT_TRUE(sig.has_value());
    EXPECT_EQ(sig->size(), slh_dsa_signature_size(SlhDsaVariant::Sha2_128s));

    const SlhDsaPublicKey<SlhDsaVariant::Sha2_128s> pub{
        .public_key = std::move(kp->public_key)
    };
    const auto verify_ok = slh_dsa_verify_impl<SlhDsaVariant::Sha2_128s, OpenSslBackend>(pub, msg, *sig);
    EXPECT_TRUE(verify_ok.has_value());
}

TEST_F(SlhDsaTests, Sha2_128s_VerifyRejectsTamperedSignature) {
    auto kp = slh_dsa_generate_key_impl<SlhDsaVariant::Sha2_128s, OpenSslBackend>();
    ASSERT_TRUE(kp.has_value());

    const auto msg = make_random_secure_buffer(kMessageSize);
    auto sig = slh_dsa_sign_impl<SlhDsaVariant::Sha2_128s, OpenSslBackend>(*kp, msg);
    ASSERT_TRUE(sig.has_value());

    (*sig)[sig->size() / 2] ^= 0xFFU;

    const SlhDsaPublicKey<SlhDsaVariant::Sha2_128s> pub{
        .public_key = std::move(kp->public_key)
    };
    const auto result = slh_dsa_verify_impl<SlhDsaVariant::Sha2_128s, OpenSslBackend>(pub, msg, *sig);
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::VerificationFailed);
}

TEST_F(SlhDsaTests, Sha2_128s_VerifyRejectsTamperedMessage) {
    auto kp = slh_dsa_generate_key_impl<SlhDsaVariant::Sha2_128s, OpenSslBackend>();
    ASSERT_TRUE(kp.has_value());

    const auto msg = make_random_secure_buffer(kMessageSize);
    const auto sig = slh_dsa_sign_impl<SlhDsaVariant::Sha2_128s, OpenSslBackend>(*kp, msg);
    ASSERT_TRUE(sig.has_value());

    auto tampered = make_random_secure_buffer(kMessageSize);
    // Ensure the tampered message differs from msg.
    tampered[0] = static_cast<CryptoByte>(msg[0] ^ 0x01U);

    const SlhDsaPublicKey<SlhDsaVariant::Sha2_128s> pub{
        .public_key = std::move(kp->public_key)
    };
    const auto result = slh_dsa_verify_impl<SlhDsaVariant::Sha2_128s, OpenSslBackend>(pub, tampered, *sig);
    EXPECT_FALSE(result.has_value());
}

TEST_F(SlhDsaTests, Sha2_128s_ExportImportRoundTrip) {
    auto kp = slh_dsa_generate_key_impl<SlhDsaVariant::Sha2_128s, OpenSslBackend>();
    ASSERT_TRUE(kp.has_value());

    // Copy the exported key bytes so we can re-import them.
    SecureBuffer priv_copy = copy_secure_buffer(kp->private_key);
    SecureBuffer pub_copy  = copy_secure_buffer(kp->public_key);

    const SlhDsaKeyPair<SlhDsaVariant::Sha2_128s> kp2{
        .private_key = std::move(priv_copy),
        .public_key  = copy_secure_buffer(kp->public_key),
    };
    const auto msg = make_random_secure_buffer(kMessageSize);
    const auto sig = slh_dsa_sign_impl<SlhDsaVariant::Sha2_128s, OpenSslBackend>(kp2, msg);
    ASSERT_TRUE(sig.has_value());

    const SlhDsaPublicKey<SlhDsaVariant::Sha2_128s> pub{ .public_key = std::move(pub_copy) };
    const auto verify_r = slh_dsa_verify_impl<SlhDsaVariant::Sha2_128s, OpenSslBackend>(pub, msg, *sig);
    EXPECT_TRUE(verify_r.has_value());
}


// --- SHA2-128f ---

TEST_F(SlhDsaTests, Sha2_128f_SignVerifyRoundTrip) {
    auto kp = slh_dsa_generate_key_impl<SlhDsaVariant::Sha2_128f, OpenSslBackend>();
    ASSERT_TRUE(kp.has_value());
    EXPECT_EQ(kp->private_key.size(), slh_dsa_private_key_size(SlhDsaVariant::Sha2_128f));
    EXPECT_EQ(kp->public_key.size(),  slh_dsa_public_key_size(SlhDsaVariant::Sha2_128f));

    const auto msg = make_random_secure_buffer(kMessageSize);
    const auto sig = slh_dsa_sign_impl<SlhDsaVariant::Sha2_128f, OpenSslBackend>(*kp, msg);
    ASSERT_TRUE(sig.has_value());
    EXPECT_EQ(sig->size(), slh_dsa_signature_size(SlhDsaVariant::Sha2_128f));

    const SlhDsaPublicKey<SlhDsaVariant::Sha2_128f> pub{ .public_key = std::move(kp->public_key) };
    const auto verify_r = slh_dsa_verify_impl<SlhDsaVariant::Sha2_128f, OpenSslBackend>(pub, msg, *sig);
    EXPECT_TRUE(verify_r.has_value());
}


// --- SHA2-192s ---

TEST_F(SlhDsaTests, Sha2_192s_SignVerifyRoundTrip) {
    auto kp = slh_dsa_generate_key_impl<SlhDsaVariant::Sha2_192s, OpenSslBackend>();
    ASSERT_TRUE(kp.has_value());
    EXPECT_EQ(kp->private_key.size(), slh_dsa_private_key_size(SlhDsaVariant::Sha2_192s));
    EXPECT_EQ(kp->public_key.size(),  slh_dsa_public_key_size(SlhDsaVariant::Sha2_192s));

    const auto msg = make_random_secure_buffer(kMessageSize);
    const auto sig = slh_dsa_sign_impl<SlhDsaVariant::Sha2_192s, OpenSslBackend>(*kp, msg);
    ASSERT_TRUE(sig.has_value());
    EXPECT_EQ(sig->size(), slh_dsa_signature_size(SlhDsaVariant::Sha2_192s));

    const SlhDsaPublicKey<SlhDsaVariant::Sha2_192s> pub{ .public_key = std::move(kp->public_key) };
    const auto verify_r = slh_dsa_verify_impl<SlhDsaVariant::Sha2_192s, OpenSslBackend>(pub, msg, *sig);
    EXPECT_TRUE(verify_r.has_value());
}


// --- SHA2-192f ---

TEST_F(SlhDsaTests, Sha2_192f_SignVerifyRoundTrip) {
    auto kp = slh_dsa_generate_key_impl<SlhDsaVariant::Sha2_192f, OpenSslBackend>();
    ASSERT_TRUE(kp.has_value());

    const auto msg = make_random_secure_buffer(kMessageSize);
    const auto sig = slh_dsa_sign_impl<SlhDsaVariant::Sha2_192f, OpenSslBackend>(*kp, msg);
    ASSERT_TRUE(sig.has_value());
    EXPECT_EQ(sig->size(), slh_dsa_signature_size(SlhDsaVariant::Sha2_192f));

    const SlhDsaPublicKey<SlhDsaVariant::Sha2_192f> pub{ .public_key = std::move(kp->public_key) };
    const auto verify_r = slh_dsa_verify_impl<SlhDsaVariant::Sha2_192f, OpenSslBackend>(pub, msg, *sig);
    EXPECT_TRUE(verify_r.has_value());
}


// --- SHA2-256s ---

TEST_F(SlhDsaTests, Sha2_256s_SignVerifyRoundTrip) {
    auto kp = slh_dsa_generate_key_impl<SlhDsaVariant::Sha2_256s, OpenSslBackend>();
    ASSERT_TRUE(kp.has_value());

    const auto msg = make_random_secure_buffer(kMessageSize);
    const auto sig = slh_dsa_sign_impl<SlhDsaVariant::Sha2_256s, OpenSslBackend>(*kp, msg);
    ASSERT_TRUE(sig.has_value());
    EXPECT_EQ(sig->size(), slh_dsa_signature_size(SlhDsaVariant::Sha2_256s));

    const SlhDsaPublicKey<SlhDsaVariant::Sha2_256s> pub{ .public_key = std::move(kp->public_key) };
    const auto verify_r = slh_dsa_verify_impl<SlhDsaVariant::Sha2_256s, OpenSslBackend>(pub, msg, *sig);
    EXPECT_TRUE(verify_r.has_value());
}


// --- SHA2-256f ---

TEST_F(SlhDsaTests, Sha2_256f_SignVerifyRoundTrip) {
    auto kp = slh_dsa_generate_key_impl<SlhDsaVariant::Sha2_256f, OpenSslBackend>();
    ASSERT_TRUE(kp.has_value());

    const auto msg = make_random_secure_buffer(kMessageSize);
    const auto sig = slh_dsa_sign_impl<SlhDsaVariant::Sha2_256f, OpenSslBackend>(*kp, msg);
    ASSERT_TRUE(sig.has_value());
    EXPECT_EQ(sig->size(), slh_dsa_signature_size(SlhDsaVariant::Sha2_256f));

    const SlhDsaPublicKey<SlhDsaVariant::Sha2_256f> pub{ .public_key = std::move(kp->public_key) };
    const auto verify_r = slh_dsa_verify_impl<SlhDsaVariant::Sha2_256f, OpenSslBackend>(pub, msg, *sig);
    EXPECT_TRUE(verify_r.has_value());
}

#endif  // SAFE_CRYPTO_PROVIDER_OPENSSL
