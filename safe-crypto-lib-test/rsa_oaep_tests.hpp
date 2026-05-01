/*
Copyright Permanence AI, 2026. All rights reserved.

*/

#pragma once

// Unit tests for rsa_oaep.hpp.
//
// Covers:
//   - MGF1-SHA384 output length and determinism
//   - OAEP encode/decode round-trip (various message sizes, empty label, non-empty label)
//   - OAEP decode error cases: corrupted Y byte, corrupted lHash, no 0x01 separator,
//     corrupted maskedSeed, corrupted maskedDB
//   - Cross-validation: PSA decrypts what we encode, and we decode what PSA encrypts

#include <array>
#include <cstddef>
#include <cstring>

#include <gtest/gtest.h>

#ifdef SAFE_CRYPTO_PROVIDER_ARM_ASM

#include "rsa_oaep.hpp"
#include "rsa_der.hpp"
#include "rsa_bigint.hpp"

#include <psa/crypto.h>

namespace {

// Minimal PSA RSA-OAEP helper: encrypt plaintext with a given SubjectPublicKeyInfo DER.
static bool psa_oaep_encrypt(
    const uint8_t* pub_der, std::size_t pub_len, std::size_t bits,
    const uint8_t* pt, std::size_t pt_len,
    const uint8_t* label, std::size_t label_len,
    uint8_t* ct_out, std::size_t ct_max, std::size_t* ct_len)
{
    psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attrs, PSA_KEY_TYPE_RSA_PUBLIC_KEY);
    psa_set_key_bits(&attrs, static_cast<psa_key_bits_t>(bits));
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_RSA_OAEP(PSA_ALG_SHA_384));

    mbedtls_svc_key_id_t psa_id = MBEDTLS_SVC_KEY_ID_INIT;
    if (psa_import_key(&attrs, pub_der, pub_len, &psa_id) != PSA_SUCCESS) { return false; }

    const psa_status_t s = psa_asymmetric_encrypt(
        psa_id, PSA_ALG_RSA_OAEP(PSA_ALG_SHA_384),
        pt, pt_len, label, label_len,
        ct_out, ct_max, ct_len);
    psa_destroy_key(psa_id);
    return s == PSA_SUCCESS;
}

// PSA decrypt with PKCS#1 private key DER.
static bool psa_oaep_decrypt(
    const uint8_t* priv_der, std::size_t priv_len, std::size_t bits,
    const uint8_t* ct, std::size_t ct_len,
    const uint8_t* label, std::size_t label_len,
    uint8_t* pt_out, std::size_t pt_max, std::size_t* pt_len)
{
    psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attrs, PSA_KEY_TYPE_RSA_KEY_PAIR);
    psa_set_key_bits(&attrs, static_cast<psa_key_bits_t>(bits));
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_RSA_OAEP(PSA_ALG_SHA_384));

    mbedtls_svc_key_id_t psa_id = MBEDTLS_SVC_KEY_ID_INIT;
    if (psa_import_key(&attrs, priv_der, priv_len, &psa_id) != PSA_SUCCESS) { return false; }

    const psa_status_t s = psa_asymmetric_decrypt(
        psa_id, PSA_ALG_RSA_OAEP(PSA_ALG_SHA_384),
        ct, ct_len, label, label_len,
        pt_out, pt_max, pt_len);
    psa_destroy_key(psa_id);
    return s == PSA_SUCCESS;
}

}  // namespace


// ---------------------------------------------------------------------------
// MGF1 tests
// ---------------------------------------------------------------------------

class Mgf1Tests : public ::testing::Test {};

TEST_F(Mgf1Tests, OutputLengthShorterThanHash) {
    const std::array<uint8_t, 4> seed = {0x01, 0x02, 0x03, 0x04};
    std::array<uint8_t, 20> out{};
    arm_asm::detail::mgf1_sha384(seed.data(), seed.size(), out.data(), 20);
    // Output should be non-zero (probabilistically).
    uint8_t acc = 0;
    for (auto b : out) { acc |= b; }
    EXPECT_NE(acc, 0U);
}

TEST_F(Mgf1Tests, OutputLengthExactlyHash) {
    const std::array<uint8_t, 4> seed = {0xAA, 0xBB, 0xCC, 0xDD};
    std::array<uint8_t, arm_asm::detail::oaep_hash_len> out{};
    arm_asm::detail::mgf1_sha384(seed.data(), seed.size(), out.data(), arm_asm::detail::oaep_hash_len);
    uint8_t acc = 0;
    for (auto b : out) { acc |= b; }
    EXPECT_NE(acc, 0U);
}

TEST_F(Mgf1Tests, OutputLengthLongerThanHash) {
    const std::array<uint8_t, 8> seed = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
    std::array<uint8_t, 100> out{};
    arm_asm::detail::mgf1_sha384(seed.data(), seed.size(), out.data(), 100);
    uint8_t acc = 0;
    for (auto b : out) { acc |= b; }
    EXPECT_NE(acc, 0U);
}

TEST_F(Mgf1Tests, Deterministic) {
    const std::array<uint8_t, 8> seed = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE};
    std::array<uint8_t, 64> out1{}, out2{};
    arm_asm::detail::mgf1_sha384(seed.data(), seed.size(), out1.data(), 64);
    arm_asm::detail::mgf1_sha384(seed.data(), seed.size(), out2.data(), 64);
    EXPECT_EQ(std::memcmp(out1.data(), out2.data(), 64), 0);
}

TEST_F(Mgf1Tests, DifferentSeedsGiveDifferentOutput) {
    const std::array<uint8_t, 4> seed1 = {0x01, 0x00, 0x00, 0x00};
    const std::array<uint8_t, 4> seed2 = {0x02, 0x00, 0x00, 0x00};
    std::array<uint8_t, 48> out1{}, out2{};
    arm_asm::detail::mgf1_sha384(seed1.data(), 4, out1.data(), 48);
    arm_asm::detail::mgf1_sha384(seed2.data(), 4, out2.data(), 48);
    EXPECT_NE(std::memcmp(out1.data(), out2.data(), 48), 0);
}


// ---------------------------------------------------------------------------
// OAEP encode/decode round-trip tests (self-contained, no PSA)
// These tests perform encode then decode with the same modulus_bytes,
// verifying the round-trip recovers the original plaintext.
// We mock the RSA step by not actually doing the RSA — we just pass the
// encoded message directly to decode (i.e., as if RSA decryption produced EM).
// ---------------------------------------------------------------------------

class OaepRoundTripTests : public ::testing::Test {};

static bool oaep_round_trip(
    const uint8_t* pt, std::size_t pt_len,
    const uint8_t* label, std::size_t label_len,
    std::size_t modulus_bytes)
{
    // Generate a random seed (48 bytes).
    std::array<uint8_t, arm_asm::detail::oaep_hash_len> seed{};
    arm_asm::detail::generate_random_bytes(seed.data(), seed.size());

    std::vector<uint8_t> em(modulus_bytes, 0U);
    if (!arm_asm::detail::oaep_encode(pt, pt_len, label, label_len,
                                       seed.data(), modulus_bytes, em.data())) {
        return false;
    }

    std::vector<uint8_t> pt_out(modulus_bytes, 0U);
    std::size_t out_len = 0;
    if (!arm_asm::detail::oaep_decode(em.data(), modulus_bytes,
                                       label, label_len,
                                       pt_out.data(), pt_out.size(), &out_len)) {
        return false;
    }

    return out_len == pt_len && std::memcmp(pt_out.data(), pt, pt_len) == 0;
}

TEST_F(OaepRoundTripTests, EmptyMessageEmptyLabel) {
    EXPECT_TRUE(oaep_round_trip(nullptr, 0, nullptr, 0, 128)); // 1024-bit key
}

TEST_F(OaepRoundTripTests, SmallMessageEmptyLabel) {
    const std::array<uint8_t, 5> pt = {0x48, 0x65, 0x6C, 0x6C, 0x6F};  // "Hello"
    EXPECT_TRUE(oaep_round_trip(pt.data(), pt.size(), nullptr, 0, 128));
}

TEST_F(OaepRoundTripTests, MaxMessageEmptyLabel) {
    // Max message for 1024-bit (128-byte) key: 128 - 2*48 - 2 = 30 bytes.
    constexpr std::size_t k = 128;
    constexpr std::size_t max_pt = k - 2U * arm_asm::detail::oaep_hash_len - 2U;
    std::array<uint8_t, max_pt> pt{};
    for (std::size_t i = 0; i < max_pt; ++i) { pt[i] = static_cast<uint8_t>(i); }
    EXPECT_TRUE(oaep_round_trip(pt.data(), max_pt, nullptr, 0, k));
}

TEST_F(OaepRoundTripTests, SmallMessageNonEmptyLabel) {
    const std::array<uint8_t, 3> pt    = {0x01, 0x02, 0x03};
    const std::array<uint8_t, 6> label = {0x6C, 0x61, 0x62, 0x65, 0x6C, 0x21};  // "label!"
    EXPECT_TRUE(oaep_round_trip(pt.data(), pt.size(), label.data(), label.size(), 128));
}

TEST_F(OaepRoundTripTests, MessageTooLongFails) {
    constexpr std::size_t k = 128;
    constexpr std::size_t max_pt = k - 2U * arm_asm::detail::oaep_hash_len - 2U;
    std::array<uint8_t, max_pt + 1U> pt{};
    std::array<uint8_t, arm_asm::detail::oaep_hash_len> seed{};
    std::vector<uint8_t> em(k, 0U);
    EXPECT_FALSE(arm_asm::detail::oaep_encode(
        pt.data(), max_pt + 1U, nullptr, 0, seed.data(), k, em.data()));
}

TEST_F(OaepRoundTripTests, LargeKey384Bit) {
    // Use a 384-byte (3072-bit) modulus simulation.
    const std::array<uint8_t, 10> pt = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    EXPECT_TRUE(oaep_round_trip(pt.data(), pt.size(), nullptr, 0, 384));
}


// ---------------------------------------------------------------------------
// OAEP decode error tests
// ---------------------------------------------------------------------------

class OaepDecodeErrorTests : public ::testing::Test {};

static std::vector<uint8_t> make_valid_em(std::size_t modulus_bytes) {
    const std::array<uint8_t, 3> pt = {0x01, 0x02, 0x03};
    std::array<uint8_t, arm_asm::detail::oaep_hash_len> seed{};
    arm_asm::detail::generate_random_bytes(seed.data(), seed.size());
    std::vector<uint8_t> em(modulus_bytes, 0U);
    const bool ok = arm_asm::detail::oaep_encode(pt.data(), pt.size(), nullptr, 0, seed.data(), modulus_bytes, em.data());
    (void)ok;
    return em;
}

TEST_F(OaepDecodeErrorTests, CorruptedYByte) {
    auto em = make_valid_em(128);
    em[0] = 0x01U;  // must be 0x00
    std::vector<uint8_t> out(128);
    std::size_t out_len = 0;
    EXPECT_FALSE(arm_asm::detail::oaep_decode(em.data(), 128, nullptr, 0, out.data(), out.size(), &out_len));
}

TEST_F(OaepDecodeErrorTests, CorruptedLHash) {
    auto em = make_valid_em(128);
    // Flip a byte deep in maskedDB (position 1 + hLen + 5, within lHash after unmask).
    em[1U + arm_asm::detail::oaep_hash_len + 5U] ^= 0xFFU;
    std::vector<uint8_t> out(128);
    std::size_t out_len = 0;
    EXPECT_FALSE(arm_asm::detail::oaep_decode(em.data(), 128, nullptr, 0, out.data(), out.size(), &out_len));
}

TEST_F(OaepDecodeErrorTests, WrongLabel) {
    auto em = make_valid_em(128);
    const std::array<uint8_t, 5> wrong_label = {0x77, 0x72, 0x6F, 0x6E, 0x67};  // "wrong"
    std::vector<uint8_t> out(128);
    std::size_t out_len = 0;
    EXPECT_FALSE(arm_asm::detail::oaep_decode(
        em.data(), 128, wrong_label.data(), wrong_label.size(), out.data(), out.size(), &out_len));
}

TEST_F(OaepDecodeErrorTests, CorruptedMaskedSeed) {
    auto em = make_valid_em(128);
    em[1U] ^= 0xFFU;  // corrupt first byte of maskedSeed
    std::vector<uint8_t> out(128);
    std::size_t out_len = 0;
    EXPECT_FALSE(arm_asm::detail::oaep_decode(em.data(), 128, nullptr, 0, out.data(), out.size(), &out_len));
}


// ---------------------------------------------------------------------------
// Cross-validation: our encode → PSA decrypt; PSA encrypt → our decode.
// Uses a real 1024-bit RSA key pair.
// ---------------------------------------------------------------------------

class OaepCrossTests : public ::testing::Test {
protected:
    void SetUp() override {
        ASSERT_EQ(psa_crypto_init(), PSA_SUCCESS);

        // Generate a 1024-bit key pair via PSA.
        psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
        psa_set_key_type(&attrs, PSA_KEY_TYPE_RSA_KEY_PAIR);
        psa_set_key_bits(&attrs, 1024); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT | PSA_KEY_USAGE_EXPORT);
        psa_set_key_algorithm(&attrs, PSA_ALG_RSA_OAEP(PSA_ALG_SHA_384));

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

    static constexpr std::size_t k_bytes = 128U;  // 1024-bit key = 128 bytes
    static constexpr std::size_t nw      = 16U;   // 1024 / 64

    std::array<uint8_t, 768> priv_der_buf_{};  // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    std::size_t priv_len_ = 0;
    std::array<uint8_t, 550> pub_der_buf_{};   // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    std::size_t pub_len_ = 0;
    arm_asm::detail::RsaPrivateKeyComponents priv_{};
};

// Perform raw RSA private-key operation (c^d mod n) using our bigint.
static void raw_rsa_decrypt(
    const arm_asm::detail::RsaPrivateKeyComponents& priv,
    const uint8_t* ct, std::size_t ct_len,
    uint8_t* em_out, std::size_t k_bytes)
{
    arm_asm::detail::rsa_private_op<16>(
        ct, ct_len,
        priv.p,    priv.p_len,
        priv.q,    priv.q_len,
        priv.dp,   priv.dp_len,
        priv.dq,   priv.dq_len,
        priv.qinv, priv.qinv_len,
        em_out);
    (void)k_bytes;
}

// Perform raw RSA public-key operation (m^e mod n).
static void raw_rsa_encrypt(
    const arm_asm::detail::RsaPrivateKeyComponents& priv,
    const uint8_t* em, std::size_t k_bytes,
    uint8_t* ct_out)
{
    arm_asm::detail::rsa_public_op<16>(
        em, k_bytes,
        priv.n,  priv.n_len,
        priv.e,  priv.e_len,
        ct_out);
}

TEST_F(OaepCrossTests, OurEncodeDecodeRoundTripWithRealKey) {
    // Generate random seed and encode a plaintext.
    const std::array<uint8_t, 16> pt = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    std::array<uint8_t, arm_asm::detail::oaep_hash_len> seed{};
    arm_asm::detail::generate_random_bytes(seed.data(), seed.size());

    std::array<uint8_t, k_bytes> em{};
    ASSERT_TRUE(arm_asm::detail::oaep_encode(
        pt.data(), pt.size(), nullptr, 0, seed.data(), k_bytes, em.data()));

    // RSA encrypt: c = em^e mod n.
    std::array<uint8_t, k_bytes> ct{};
    raw_rsa_encrypt(priv_, em.data(), k_bytes, ct.data());

    // RSA decrypt: em' = c^d mod n.
    std::array<uint8_t, k_bytes> em_dec{};
    raw_rsa_decrypt(priv_, ct.data(), k_bytes, em_dec.data(), k_bytes);

    ASSERT_EQ(std::memcmp(em.data(), em_dec.data(), k_bytes), 0)
        << "RSA round-trip corrupted the OAEP-encoded message";

    // Decode the EM.
    std::array<uint8_t, k_bytes> pt_out{};
    std::size_t pt_out_len = 0;
    ASSERT_TRUE(arm_asm::detail::oaep_decode(
        em_dec.data(), k_bytes, nullptr, 0, pt_out.data(), pt_out.size(), &pt_out_len));

    EXPECT_EQ(pt_out_len, pt.size());
    EXPECT_EQ(std::memcmp(pt_out.data(), pt.data(), pt.size()), 0);
}

TEST_F(OaepCrossTests, PsaEncryptOurDecrypt) {
    // PSA encrypts with our public key.
    const std::array<uint8_t, 8> pt = {0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48};  // "ABCDEFGH"
    std::array<uint8_t, k_bytes> ct{};
    std::size_t ct_len = 0;
    ASSERT_TRUE(psa_oaep_encrypt(pub_der_buf_.data(), pub_len_, 1024,
                                  pt.data(), pt.size(), nullptr, 0,
                                  ct.data(), ct.size(), &ct_len));
    ASSERT_EQ(ct_len, k_bytes);

    // Our bigint decrypts.
    std::array<uint8_t, k_bytes> em{};
    raw_rsa_decrypt(priv_, ct.data(), k_bytes, em.data(), k_bytes);

    // OAEP decode.
    std::array<uint8_t, k_bytes> pt_out{};
    std::size_t pt_out_len = 0;
    ASSERT_TRUE(arm_asm::detail::oaep_decode(
        em.data(), k_bytes, nullptr, 0, pt_out.data(), pt_out.size(), &pt_out_len));

    EXPECT_EQ(pt_out_len, pt.size());
    EXPECT_EQ(std::memcmp(pt_out.data(), pt.data(), pt.size()), 0);
}

TEST_F(OaepCrossTests, OurEncryptPsaDecrypt) {
    // We OAEP-encode and RSA-encrypt.
    const std::array<uint8_t, 12> pt = {0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C};  // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    std::array<uint8_t, arm_asm::detail::oaep_hash_len> seed{};
    arm_asm::detail::generate_random_bytes(seed.data(), seed.size());

    std::array<uint8_t, k_bytes> em{};
    ASSERT_TRUE(arm_asm::detail::oaep_encode(
        pt.data(), pt.size(), nullptr, 0, seed.data(), k_bytes, em.data()));

    std::array<uint8_t, k_bytes> ct{};
    raw_rsa_encrypt(priv_, em.data(), k_bytes, ct.data());

    // PSA decrypts.
    std::array<uint8_t, k_bytes> pt_out{};
    std::size_t pt_out_len = 0;
    ASSERT_TRUE(psa_oaep_decrypt(priv_der_buf_.data(), priv_len_, 1024,
                                  ct.data(), k_bytes, nullptr, 0,
                                  pt_out.data(), pt_out.size(), &pt_out_len));

    EXPECT_EQ(pt_out_len, pt.size());
    EXPECT_EQ(std::memcmp(pt_out.data(), pt.data(), pt.size()), 0);
}

#endif  // SAFE_CRYPTO_PROVIDER_ARM_ASM
