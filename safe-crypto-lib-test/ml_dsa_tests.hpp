// SPDX-License-Identifier: Apache-2.0

#pragma once

// ML-DSA (FIPS 204) tests.
// Active for SAFE_CRYPTO_PROVIDER_OPENSSL and SAFE_CRYPTO_PQC_LIBOQS builds.

#include <cstddef>
#include <cstring>

#include <gtest/gtest.h>

#if defined(SAFE_CRYPTO_PROVIDER_OPENSSL)
#include "ml_dsa_variant.hpp"
#include "openssl_backend.hpp"
#include "pqc_dsa.hpp"
#include "test_utils.hpp"
using MlDsaBackend = OpenSslBackend;
#elif defined(SAFE_CRYPTO_PQC_LIBOQS) && defined(SAFE_CRYPTO_PROVIDER_ARM_ASM)
#include "arm_asm_backend.hpp"
#include "ml_dsa_variant.hpp"
#include "pqc_dsa.hpp"
#include "test_utils.hpp"
using MlDsaBackend = ArmAsmBackend;
#elif defined(SAFE_CRYPTO_PQC_LIBOQS)
#include "ml_dsa_variant.hpp"
#include "pqc_dsa.hpp"
#include "psa_mbedtls_backend.hpp"
#include "test_utils.hpp"
using MlDsaBackend = RealPsaBackend;
#endif

#if defined(SAFE_CRYPTO_PROVIDER_OPENSSL) || defined(SAFE_CRYPTO_PQC_LIBOQS)

class MlDsaTests : public ::testing::Test {
protected:
    static constexpr std::size_t kMessageSize = 64;
};

// Copy bytes from a SecureBuffer into a fresh SecureBuffer (for test purposes only).
static SecureBuffer copy_secure_buffer_ml(const SecureBuffer& src) {
    SecureBuffer dst(src.size());
    std::memcpy(dst.data(), src.data(), src.size());
    return dst;
}


// --- ML-DSA-44 ---

TEST_F(MlDsaTests, Dsa44_KeygenProducesCorrectSizes) {
    const auto kp = ml_dsa_generate_key_impl<MlDsaVariant::Dsa44, MlDsaBackend>();
    ASSERT_TRUE(kp.has_value());
    EXPECT_EQ(kp->private_key.size(), ml_dsa_private_key_size(MlDsaVariant::Dsa44));
    EXPECT_EQ(kp->public_key.size(),  ml_dsa_public_key_size(MlDsaVariant::Dsa44));
}

TEST_F(MlDsaTests, Dsa44_SignVerifyRoundTrip) {
    auto kp = ml_dsa_generate_key_impl<MlDsaVariant::Dsa44, MlDsaBackend>();
    ASSERT_TRUE(kp.has_value());

    const auto msg = make_random_secure_buffer(kMessageSize);
    const auto sig = ml_dsa_sign_impl<MlDsaVariant::Dsa44, MlDsaBackend>(*kp, msg);
    ASSERT_TRUE(sig.has_value());
    EXPECT_EQ(sig->size(), ml_dsa_signature_size(MlDsaVariant::Dsa44));

    const MlDsaPublicKey<MlDsaVariant::Dsa44> pub{
        .public_key = std::move(kp->public_key)
    };
    const auto verify_r = ml_dsa_verify_impl<MlDsaVariant::Dsa44, MlDsaBackend>(pub, msg, *sig);
    EXPECT_TRUE(verify_r.has_value());
}

TEST_F(MlDsaTests, Dsa44_VerifyRejectsTamperedSignature) {
    auto kp = ml_dsa_generate_key_impl<MlDsaVariant::Dsa44, MlDsaBackend>();
    ASSERT_TRUE(kp.has_value());

    const auto msg = make_random_secure_buffer(kMessageSize);
    auto sig = ml_dsa_sign_impl<MlDsaVariant::Dsa44, MlDsaBackend>(*kp, msg);
    ASSERT_TRUE(sig.has_value());

    (*sig)[sig->size() / 2] ^= 0xFFU;

    const MlDsaPublicKey<MlDsaVariant::Dsa44> pub{
        .public_key = std::move(kp->public_key)
    };
    const auto result = ml_dsa_verify_impl<MlDsaVariant::Dsa44, MlDsaBackend>(pub, msg, *sig);
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::VerificationFailed);
}

TEST_F(MlDsaTests, Dsa44_VerifyRejectsTamperedMessage) {
    auto kp = ml_dsa_generate_key_impl<MlDsaVariant::Dsa44, MlDsaBackend>();
    ASSERT_TRUE(kp.has_value());

    const auto msg = make_random_secure_buffer(kMessageSize);
    const auto sig = ml_dsa_sign_impl<MlDsaVariant::Dsa44, MlDsaBackend>(*kp, msg);
    ASSERT_TRUE(sig.has_value());

    auto tampered = make_random_secure_buffer(kMessageSize);
    tampered[0] = static_cast<CryptoByte>(msg[0] ^ 0x01U);

    const MlDsaPublicKey<MlDsaVariant::Dsa44> pub{
        .public_key = std::move(kp->public_key)
    };
    const auto result = ml_dsa_verify_impl<MlDsaVariant::Dsa44, MlDsaBackend>(pub, tampered, *sig);
    EXPECT_FALSE(result.has_value());
}

TEST_F(MlDsaTests, Dsa44_ExportImportRoundTrip) {
    auto kp = ml_dsa_generate_key_impl<MlDsaVariant::Dsa44, MlDsaBackend>();
    ASSERT_TRUE(kp.has_value());

    SecureBuffer priv_copy = copy_secure_buffer_ml(kp->private_key);
    SecureBuffer pub_copy  = copy_secure_buffer_ml(kp->public_key);

    const MlDsaKeyPair<MlDsaVariant::Dsa44> kp2{
        .private_key = std::move(priv_copy),
        .public_key  = copy_secure_buffer_ml(kp->public_key),
    };
    const auto msg = make_random_secure_buffer(kMessageSize);
    const auto sig = ml_dsa_sign_impl<MlDsaVariant::Dsa44, MlDsaBackend>(kp2, msg);
    ASSERT_TRUE(sig.has_value());

    const MlDsaPublicKey<MlDsaVariant::Dsa44> pub{ .public_key = std::move(pub_copy) };
    const auto verify_r = ml_dsa_verify_impl<MlDsaVariant::Dsa44, MlDsaBackend>(pub, msg, *sig);
    EXPECT_TRUE(verify_r.has_value());
}


// --- ML-DSA-65 ---

TEST_F(MlDsaTests, Dsa65_SignVerifyRoundTrip) {
    auto kp = ml_dsa_generate_key_impl<MlDsaVariant::Dsa65, MlDsaBackend>();
    ASSERT_TRUE(kp.has_value());
    EXPECT_EQ(kp->private_key.size(), ml_dsa_private_key_size(MlDsaVariant::Dsa65));
    EXPECT_EQ(kp->public_key.size(),  ml_dsa_public_key_size(MlDsaVariant::Dsa65));

    const auto msg = make_random_secure_buffer(kMessageSize);
    const auto sig = ml_dsa_sign_impl<MlDsaVariant::Dsa65, MlDsaBackend>(*kp, msg);
    ASSERT_TRUE(sig.has_value());
    EXPECT_EQ(sig->size(), ml_dsa_signature_size(MlDsaVariant::Dsa65));

    const MlDsaPublicKey<MlDsaVariant::Dsa65> pub{ .public_key = std::move(kp->public_key) };
    const auto verify_r = ml_dsa_verify_impl<MlDsaVariant::Dsa65, MlDsaBackend>(pub, msg, *sig);
    EXPECT_TRUE(verify_r.has_value());
}


// --- ML-DSA-87 ---

TEST_F(MlDsaTests, Dsa87_SignVerifyRoundTrip) {
    auto kp = ml_dsa_generate_key_impl<MlDsaVariant::Dsa87, MlDsaBackend>();
    ASSERT_TRUE(kp.has_value());
    EXPECT_EQ(kp->private_key.size(), ml_dsa_private_key_size(MlDsaVariant::Dsa87));
    EXPECT_EQ(kp->public_key.size(),  ml_dsa_public_key_size(MlDsaVariant::Dsa87));

    const auto msg = make_random_secure_buffer(kMessageSize);
    const auto sig = ml_dsa_sign_impl<MlDsaVariant::Dsa87, MlDsaBackend>(*kp, msg);
    ASSERT_TRUE(sig.has_value());
    EXPECT_EQ(sig->size(), ml_dsa_signature_size(MlDsaVariant::Dsa87));

    const MlDsaPublicKey<MlDsaVariant::Dsa87> pub{ .public_key = std::move(kp->public_key) };
    const auto verify_r = ml_dsa_verify_impl<MlDsaVariant::Dsa87, MlDsaBackend>(pub, msg, *sig);
    EXPECT_TRUE(verify_r.has_value());
}

#endif  // SAFE_CRYPTO_PROVIDER_OPENSSL || SAFE_CRYPTO_PQC_LIBOQS
