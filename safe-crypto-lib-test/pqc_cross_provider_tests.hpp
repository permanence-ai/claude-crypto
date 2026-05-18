// SPDX-License-Identifier: Apache-2.0

#pragma once

// PQC cross-provider parity tests: OpenSSL vs ARM ASM+liboqs.
//
// Active only when BOTH SAFE_CRYPTO_PROVIDER_OPENSSL and SAFE_CRYPTO_PQC_LIBOQS
// are defined (i.e. a build configured with SAFE_CRYPTO_ACTIVE_PROVIDER=OPENSSL
// and SAFE_CRYPTO_PQC=LIBOQS).
//
// For ML-DSA: generate a key pair with one provider, sign with it, export the
// raw key bytes, import into the other provider, and verify — in both directions.
// This confirms that both implementations produce the same wire format.
//
// For ML-KEM: generate a key pair with one provider, export the public key,
// import into the other provider and encapsulate, then decapsulate with the
// original provider's private key.  Both directions are tested.  The shared
// secrets must match byte-for-byte.

#include <cstddef>
#include <cstring>

#include <gtest/gtest.h>

#if defined(SAFE_CRYPTO_PROVIDER_OPENSSL) && defined(SAFE_CRYPTO_PQC_LIBOQS)

#include "arm_asm_backend.hpp"
#include "ml_dsa_variant.hpp"
#include "ml_kem_variant.hpp"
#include "openssl_backend.hpp"
#include "pqc_dsa.hpp"
#include "pqc_kem.hpp"
#include "secure_buffer.hpp"
#include "test_utils.hpp"

// Copy bytes from a SecureBuffer into a fresh SecureBuffer.
static SecureBuffer pqc_copy(const SecureBuffer& src) {
    SecureBuffer dst(src.size());
    std::memcpy(dst.data(), src.data(), src.size());
    return dst;
}

class PqcCrossProviderTest : public ::testing::Test {};


// ---------------------------------------------------------------------------
// ML-DSA cross-verify helpers
// ---------------------------------------------------------------------------

template<MlDsaVariant V>
static void run_ml_dsa_cross_verify(const char* label) {
    constexpr std::size_t kMsgSize = 64;
    const auto msg = make_random_secure_buffer(kMsgSize);

    // ---- OpenSSL signs, ARM ASM+liboqs verifies ----------------------------
    {
        // Generate key with OpenSSL.
        auto ossl_kp = ml_dsa_generate_key_impl<V, OpenSslBackend>();
        ASSERT_TRUE(ossl_kp.has_value()) << label << " OpenSSL keygen failed";

        // Sign with OpenSSL.
        const auto sig = ml_dsa_sign_impl<V, OpenSslBackend>(*ossl_kp, msg);
        ASSERT_TRUE(sig.has_value()) << label << " OpenSSL sign failed";

        // Import public key into ARM ASM backend.
        auto arm_pub_attrs = ArmAsmBackend::make_ml_dsa_verify_attrs(V);
        ArmAsmBackend::KeyId arm_pub_id = ArmAsmBackend::null_key_id();
        { auto r_ = ArmAsmBackend::import_key(&arm_pub_attrs, CByteVSpan{ossl_kp->public_key.data(), ossl_kp->public_key.size()}); ASSERT_TRUE(r_.has_value()) << label << " ARM public key import failed (OpenSSL→ARM)"; arm_pub_id = r_.value(); }

        EXPECT_EQ(ArmAsmBackend::verify_message(
            arm_pub_id, ArmAsmBackend::alg_ml_dsa(V),
            CByteVSpan{msg.data(), msg.size()},
            CByteVSpan{sig->data(), sig->size()}), ArmAsmBackend::ok)
            << label << " ARM rejected OpenSSL ML-DSA signature";

        (void)ArmAsmBackend::destroy_key(arm_pub_id);
    }

    // ---- ARM ASM+liboqs signs, OpenSSL verifies ----------------------------
    {
        // Generate key with ARM ASM.
        auto arm_gen_attrs = ArmAsmBackend::make_ml_dsa_generate_attrs(V);
        ArmAsmBackend::KeyId arm_priv_id = ArmAsmBackend::null_key_id();
        { auto r_ = ArmAsmBackend::generate_key(&arm_gen_attrs); ASSERT_TRUE(r_.has_value()) << label << " ARM keygen failed"; arm_priv_id = r_.value(); }

        // Export ARM private key and public key.
        const auto priv_result = ArmAsmBackend::export_key(arm_priv_id);
        ASSERT_TRUE(priv_result.has_value()) << label << " ARM export_key failed";
        const SecureBuffer& arm_priv = *priv_result;
        const auto pub_result = ArmAsmBackend::export_public_key(arm_priv_id);
        ASSERT_TRUE(pub_result.has_value()) << label << " ARM export_public_key failed";
        const SecureBuffer& arm_pub = *pub_result;

        // Sign with ARM ASM.
        auto arm_sig_result = ArmAsmBackend::sign_message(
            arm_priv_id, ArmAsmBackend::alg_ml_dsa(V),
            CByteVSpan{msg.data(), msg.size()});
        ASSERT_TRUE(arm_sig_result.has_value()) << label << " ARM sign failed";
        SecureBuffer arm_sig = std::move(arm_sig_result).value();
        (void)ArmAsmBackend::destroy_key(arm_priv_id);

        // Import public key into OpenSSL backend and verify.
        const MlDsaPublicKey<V> ossl_pub{ .public_key = pqc_copy(arm_pub) };
        const auto verify_r = ml_dsa_verify_impl<V, OpenSslBackend>(ossl_pub, msg, arm_sig);
        ASSERT_TRUE(verify_r.has_value())
            << label << " OpenSSL ML-DSA verify returned error";
        EXPECT_TRUE(*verify_r)
            << label << " OpenSSL rejected ARM ASM ML-DSA signature";
    }
}


// ---------------------------------------------------------------------------
// ML-KEM cross-encap helpers
// ---------------------------------------------------------------------------

template<MlKemVariant V>
static void run_ml_kem_cross_encap(const char* label) {
    // ---- OpenSSL generates, ARM ASM+liboqs encapsulates, OpenSSL decapsulates ----
    {
        auto ossl_kp = ml_kem_generate_key_impl<V, OpenSslBackend>();
        ASSERT_TRUE(ossl_kp.has_value()) << label << " OpenSSL keygen failed";

        // Import OpenSSL public key into ARM ASM backend for encapsulation.
        auto arm_pub_attrs = ArmAsmBackend::make_ml_kem_encap_attrs(V);
        ArmAsmBackend::KeyId arm_pub_id = ArmAsmBackend::null_key_id();
        { auto r_ = ArmAsmBackend::import_key(&arm_pub_attrs, CByteVSpan{ossl_kp->public_key.data(), ossl_kp->public_key.size()}); ASSERT_TRUE(r_.has_value()) << label << " ARM public key import failed (OpenSSL→ARM)"; arm_pub_id = r_.value(); }

        // ARM ASM encapsulate.
        const auto encap_result = ArmAsmBackend::kem_encapsulate(arm_pub_id, ArmAsmBackend::alg_ml_kem(V));
        ASSERT_TRUE(encap_result.has_value()) << label << " ARM encapsulate failed";
        const SecureBuffer& arm_ct = encap_result->ciphertext;
        const SecureBuffer& arm_ss = encap_result->shared_secret;
        (void)ArmAsmBackend::destroy_key(arm_pub_id);

        // OpenSSL decapsulate with its own private key.
        const auto ossl_ss = ml_kem_decapsulate_impl<V, OpenSslBackend>(*ossl_kp, arm_ct);
        ASSERT_TRUE(ossl_ss.has_value()) << label << " OpenSSL decapsulate failed (ARM ct)";
        const std::size_t ss_sz = ArmAsmBackend::ml_kem_shared_secret_size(V);
        ASSERT_EQ(ossl_ss->size(), ss_sz);
        EXPECT_EQ(std::memcmp(arm_ss.data(), ossl_ss->data(), ss_sz), 0)
            << label << " shared secret mismatch (ARM encap, OpenSSL decap)";
    }

    // ---- ARM ASM+liboqs generates, OpenSSL encapsulates, ARM decapsulates ----
    {
        // Generate key pair with ARM ASM.
        auto arm_gen_attrs = ArmAsmBackend::make_ml_kem_generate_attrs(V);
        ArmAsmBackend::KeyId arm_priv_id = ArmAsmBackend::null_key_id();
        { auto r_ = ArmAsmBackend::generate_key(&arm_gen_attrs); ASSERT_TRUE(r_.has_value()) << label << " ARM keygen failed"; arm_priv_id = r_.value(); }

        const auto pub_result = ArmAsmBackend::export_public_key(arm_priv_id);
        ASSERT_TRUE(pub_result.has_value()) << label << " ARM export_public_key failed";
        const SecureBuffer& arm_pub = *pub_result;

        // OpenSSL encapsulate using ARM-generated public key.
        const MlKemPublicKey<V> ossl_pub{ .public_key = pqc_copy(arm_pub) };
        const auto ossl_encap = ml_kem_encapsulate_impl<V, OpenSslBackend>(ossl_pub);
        ASSERT_TRUE(ossl_encap.has_value()) << label << " OpenSSL encapsulate failed";

        // ARM ASM decapsulate.
        const auto ss_result = ArmAsmBackend::kem_decapsulate(
            arm_priv_id, ArmAsmBackend::alg_ml_kem(V),
            CByteVSpan{ossl_encap->ciphertext.data(), ossl_encap->ciphertext.size()});
        ASSERT_TRUE(ss_result.has_value()) << label << " ARM decapsulate failed (OpenSSL ct)";
        const SecureBuffer& arm_ss = *ss_result;
        (void)ArmAsmBackend::destroy_key(arm_priv_id);

        ASSERT_EQ(ossl_encap->shared_secret.size(), arm_ss.size());
        const std::size_t ss_sz = ArmAsmBackend::ml_kem_shared_secret_size(V);
        EXPECT_EQ(std::memcmp(ossl_encap->shared_secret.data(), arm_ss.data(), ss_sz), 0)
            << label << " shared secret mismatch (OpenSSL encap, ARM decap)";
    }
}


// ---------------------------------------------------------------------------
// ML-DSA cross-verify tests
// ---------------------------------------------------------------------------

TEST_F(PqcCrossProviderTest, MlDsa44_CrossVerify) {
    run_ml_dsa_cross_verify<MlDsaVariant::Dsa44>("ML-DSA-44");
}
TEST_F(PqcCrossProviderTest, MlDsa65_CrossVerify) {
    run_ml_dsa_cross_verify<MlDsaVariant::Dsa65>("ML-DSA-65");
}
TEST_F(PqcCrossProviderTest, MlDsa87_CrossVerify) {
    run_ml_dsa_cross_verify<MlDsaVariant::Dsa87>("ML-DSA-87");
}


// ---------------------------------------------------------------------------
// ML-KEM cross-encap tests
// ---------------------------------------------------------------------------

TEST_F(PqcCrossProviderTest, MlKem512_CrossEncap) {
    run_ml_kem_cross_encap<MlKemVariant::Kem512>("ML-KEM-512");
}
TEST_F(PqcCrossProviderTest, MlKem768_CrossEncap) {
    run_ml_kem_cross_encap<MlKemVariant::Kem768>("ML-KEM-768");
}
TEST_F(PqcCrossProviderTest, MlKem1024_CrossEncap) {
    run_ml_kem_cross_encap<MlKemVariant::Kem1024>("ML-KEM-1024");
}

#endif  // SAFE_CRYPTO_PROVIDER_OPENSSL && SAFE_CRYPTO_PQC_LIBOQS
