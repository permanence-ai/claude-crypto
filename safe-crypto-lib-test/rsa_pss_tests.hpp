// SPDX-License-Identifier: Apache-2.0

#pragma once

// Unit tests for rsa_pss.hpp.
//
// Covers:
//   - PSS encode/verify round-trip (various message sizes)
//   - PSS verify rejects tampered EM (corrupted H, maskedDB, trailing byte)
//   - PSS verify rejects wrong message
//   - Cross-validation: PSA signs / we verify; we sign / PSA verifies

#include <cstddef>
#include <cstring>

#include <gtest/gtest.h>

#ifdef SAFE_CRYPTO_ARM_ASM_AVAILABLE

#include "rsa_pss.hpp"
#include "rsa_der.hpp"
#include "rsa_bigint.hpp"

#include <psa/crypto.h>


// ---------------------------------------------------------------------------
// PSS round-trip tests (no actual RSA — just EM encode/verify).
// ---------------------------------------------------------------------------

class PssRoundTripTests : public ::testing::Test {};

static bool pss_round_trip(const uint8_t* msg, std::size_t msg_len,
                            std::size_t modulus_bits)
{
    const std::size_t em_len = (modulus_bits - 1U + 7U) / 8U;
    ByteArray< arm_asm::detail::oaep_hash_len> salt{};
    arm_asm::detail::generate_random_bytes(salt.data(), salt.size());

    std::vector<CryptoByte> em(em_len, 0U);
    if (!arm_asm::detail::pss_encode(msg, msg_len, salt.data(), modulus_bits, em.data())) {
        return false;
    }
    return arm_asm::detail::pss_verify(msg, msg_len, em.data(), modulus_bits);
}

TEST_F(PssRoundTripTests, EmptyMessage) {
    EXPECT_TRUE(pss_round_trip(nullptr, 0, rsa_1024_bits));
}

TEST_F(PssRoundTripTests, SmallMessage) {
    const ByteArray< 8> msg = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    EXPECT_TRUE(pss_round_trip(msg.data(), msg.size(), rsa_1024_bits));
}

TEST_F(PssRoundTripTests, LargeMessage) {
    ByteArray< 256> msg{}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    for (std::size_t i = 0; i < msg.size(); ++i) { msg[i] = static_cast<uint8_t>(i); }
    EXPECT_TRUE(pss_round_trip(msg.data(), msg.size(), rsa_1024_bits));
}

TEST_F(PssRoundTripTests, DifferentSaltsProduceDifferentEM) {
    const ByteArray< 4> msg = {0xDE, 0xAD, 0xBE, 0xEF};
    constexpr std::size_t modulus_bits = 1024;
    const std::size_t em_len = (modulus_bits - 1U + 7U) / 8U;

    ByteArray< arm_asm::detail::oaep_hash_len> salt1{};
    ByteArray< arm_asm::detail::oaep_hash_len> salt2{};
    arm_asm::detail::generate_random_bytes(salt1.data(), salt1.size());
    arm_asm::detail::generate_random_bytes(salt2.data(), salt2.size());

    std::vector<CryptoByte> em1(em_len), em2(em_len);
    ASSERT_TRUE(arm_asm::detail::pss_encode(msg.data(), msg.size(), salt1.data(), modulus_bits, em1.data()));
    ASSERT_TRUE(arm_asm::detail::pss_encode(msg.data(), msg.size(), salt2.data(), modulus_bits, em2.data()));
    EXPECT_NE(std::memcmp(em1.data(), em2.data(), em_len), 0);
}

TEST_F(PssRoundTripTests, Large3072BitKey) {
    const ByteArray< 16> msg = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    EXPECT_TRUE(pss_round_trip(msg.data(), msg.size(), rsa_3072_bits));
}


// ---------------------------------------------------------------------------
// PSS verify error tests
// ---------------------------------------------------------------------------

class PssVerifyErrorTests : public ::testing::Test {};

static std::vector<CryptoByte> make_valid_pss_em(
    const uint8_t* msg, std::size_t msg_len, std::size_t modulus_bits)
{
    const std::size_t em_len = (modulus_bits - 1U + 7U) / 8U;
    ByteArray< arm_asm::detail::oaep_hash_len> salt{};
    arm_asm::detail::generate_random_bytes(salt.data(), salt.size());
    std::vector<CryptoByte> em(em_len, 0U);
    const bool ok = arm_asm::detail::pss_encode(msg, msg_len, salt.data(), modulus_bits, em.data());
    (void)ok;
    return em;
}

TEST_F(PssVerifyErrorTests, CorruptedTrailingByte) {
    const ByteArray< 4> msg = {0x01, 0x02, 0x03, 0x04};
    auto em = make_valid_pss_em(msg.data(), msg.size(), rsa_1024_bits);
    em.back() = 0x00U;  // must be 0xBC
    EXPECT_FALSE(arm_asm::detail::pss_verify(msg.data(), msg.size(), em.data(), rsa_1024_bits));
}

TEST_F(PssVerifyErrorTests, CorruptedH) {
    const ByteArray< 4> msg = {0x01, 0x02, 0x03, 0x04};
    auto em = make_valid_pss_em(msg.data(), msg.size(), rsa_1024_bits);
    // H occupies em[em_len - hLen - 1 .. em_len - 2].
    const std::size_t h_start = em.size() - arm_asm::detail::oaep_hash_len - 1U;
    em[h_start] ^= 0xFFU;
    EXPECT_FALSE(arm_asm::detail::pss_verify(msg.data(), msg.size(), em.data(), rsa_1024_bits));
}

TEST_F(PssVerifyErrorTests, CorruptedMaskedDB) {
    const ByteArray< 4> msg = {0x01, 0x02, 0x03, 0x04};
    auto em = make_valid_pss_em(msg.data(), msg.size(), rsa_1024_bits);
    em[em.size() / 2U] ^= 0xA5U;  // flip a byte in maskedDB
    EXPECT_FALSE(arm_asm::detail::pss_verify(msg.data(), msg.size(), em.data(), rsa_1024_bits));
}

TEST_F(PssVerifyErrorTests, WrongMessage) {
    const ByteArray< 4> msg1 = {0x01, 0x02, 0x03, 0x04};
    const ByteArray< 4> msg2 = {0x01, 0x02, 0x03, 0x05};  // one byte different
    auto em = make_valid_pss_em(msg1.data(), msg1.size(), rsa_1024_bits);
    EXPECT_FALSE(arm_asm::detail::pss_verify(msg2.data(), msg2.size(), em.data(), rsa_1024_bits));
}


// ---------------------------------------------------------------------------
// Cross-validation with PSA: PSA signs / we verify; we sign / PSA verifies.
// ---------------------------------------------------------------------------

class PssCrossTests : public ::testing::Test {
protected:
    void SetUp() override {
        ASSERT_EQ(psa_crypto_init(), PSA_SUCCESS);

        psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
        psa_set_key_type(&attrs, PSA_KEY_TYPE_RSA_KEY_PAIR);
        psa_set_key_bits(&attrs, rsa_1024_bits);
        psa_set_key_usage_flags(&attrs,
            PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE | PSA_KEY_USAGE_EXPORT);
        psa_set_key_algorithm(&attrs, PSA_ALG_RSA_PSS(PSA_ALG_SHA_384));

        mbedtls_svc_key_id_t psa_id = MBEDTLS_SVC_KEY_ID_INIT;
        ASSERT_EQ(psa_generate_key(&attrs, &psa_id), PSA_SUCCESS);

        priv_der_buf_.fill(0);
        ASSERT_EQ(psa_export_key(psa_id, priv_der_buf_.data(), priv_der_buf_.size(), &priv_len_), PSA_SUCCESS);

        pub_der_buf_.fill(0);
        ASSERT_EQ(psa_export_public_key(psa_id, pub_der_buf_.data(), pub_der_buf_.size(), &pub_len_), PSA_SUCCESS);

        psa_destroy_key(psa_id);

        ASSERT_TRUE(arm_asm::detail::rsa_parse_private_key_der(
            priv_der_buf_.data(), priv_len_, priv_));
    }

    static constexpr std::size_t k_bits  = 1024U;
    static constexpr std::size_t k_bytes = k_bits / 8U;
    static constexpr std::size_t nw      = k_bytes / 8U;

    ByteArray< 768> priv_der_buf_{}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    std::size_t priv_len_ = 0;
    ByteArray< 550> pub_der_buf_{}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    std::size_t pub_len_ = 0;
    arm_asm::detail::RsaPrivateKeyComponents priv_{};
};

TEST_F(PssCrossTests, PsaSignOurVerify) {
    const ByteArray< 10> msg = {0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)

    // PSA sign_message hashes internally and produces the full signature.
    ByteArray< k_bytes> sig{};
    std::size_t sig_len = 0;

    // Import private key into PSA for signing.
    psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attrs, PSA_KEY_TYPE_RSA_KEY_PAIR);
    psa_set_key_bits(&attrs, static_cast<psa_key_bits_t>(k_bits));
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attrs, PSA_ALG_RSA_PSS(PSA_ALG_SHA_384));

    mbedtls_svc_key_id_t psa_id = MBEDTLS_SVC_KEY_ID_INIT;
    ASSERT_EQ(psa_import_key(&attrs, priv_der_buf_.data(), priv_len_, &psa_id), PSA_SUCCESS);
    ASSERT_EQ(psa_sign_message(psa_id, PSA_ALG_RSA_PSS(PSA_ALG_SHA_384),
                                msg.data(), msg.size(),
                                sig.data(), sig.size(), &sig_len), PSA_SUCCESS);
    psa_destroy_key(psa_id);
    ASSERT_EQ(sig_len, k_bytes);

    // RSA public-key operation: em = sig^e mod n.
    ByteArray< k_bytes> em{};
    arm_asm::detail::rsa_public_op<nw>(
        sig.data(), k_bytes,
        priv_.n, priv_.n_len,
        priv_.e, priv_.e_len,
        em.data());

    EXPECT_TRUE(arm_asm::detail::pss_verify(msg.data(), msg.size(), em.data(), k_bits));
}

TEST_F(PssCrossTests, OurSignPsaVerify) {
    const ByteArray< 10> msg = {0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)

    // PSS encode.
    const std::size_t em_len = (k_bits - 1U + 7U) / 8U;
    ByteArray< arm_asm::detail::oaep_hash_len> salt{};
    arm_asm::detail::generate_random_bytes(salt.data(), salt.size());

    ByteArray< k_bytes> em{};
    ASSERT_TRUE(arm_asm::detail::pss_encode(msg.data(), msg.size(), salt.data(), k_bits, em.data()));
    ASSERT_EQ(em_len, k_bytes);

    // RSA private-key operation: sig = em^d mod n (using CRT).
    ByteArray< k_bytes> sig{};
    arm_asm::detail::rsa_private_op<nw>(
        em.data(), k_bytes,
        priv_.p,    priv_.p_len,
        priv_.q,    priv_.q_len,
        priv_.dp,   priv_.dp_len,
        priv_.dq,   priv_.dq_len,
        priv_.qinv, priv_.qinv_len,
        sig.data());

    // PSA verify_message.
    psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attrs, PSA_KEY_TYPE_RSA_PUBLIC_KEY);
    psa_set_key_bits(&attrs, static_cast<psa_key_bits_t>(k_bits));
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(&attrs, PSA_ALG_RSA_PSS(PSA_ALG_SHA_384));

    mbedtls_svc_key_id_t psa_id = MBEDTLS_SVC_KEY_ID_INIT;
    ASSERT_EQ(psa_import_key(&attrs, pub_der_buf_.data(), pub_len_, &psa_id), PSA_SUCCESS);
    const psa_status_t st = psa_verify_message(psa_id, PSA_ALG_RSA_PSS(PSA_ALG_SHA_384),
                                                msg.data(), msg.size(),
                                                sig.data(), k_bytes);
    psa_destroy_key(psa_id);
    EXPECT_EQ(st, PSA_SUCCESS);
}

#endif  // SAFE_CRYPTO_ARM_ASM_AVAILABLE
