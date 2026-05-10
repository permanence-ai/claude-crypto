// SPDX-License-Identifier: Apache-2.0

#pragma once

// Unit tests for rsa_keygen.hpp.
//
// Covers:
//   - small_e_modinv correctness
//   - miller_rabin_is_prime: rejects composites, accepts known primes
//   - rsa_generate_key_der: generates a parseable PKCS#1 DER key
//   - full round-trip: encrypt with our public-op, decrypt with our private-op

#include <cstddef>
#include <cstring>

#include <gtest/gtest.h>

#ifdef SAFE_CRYPTO_ARM_ASM_AVAILABLE

#include "rsa_keygen.hpp"
#include "rsa_bigint.hpp"
#include "rsa_der.hpp"
#include "rsa_oaep.hpp"

#include <psa/crypto.h>


// ---------------------------------------------------------------------------
// small_e_modinv tests
// ---------------------------------------------------------------------------

class SmallEModinvTests : public ::testing::Test {};

TEST_F(SmallEModinvTests, BasicCorrectness) {
    // For a known m, verify e * d ≡ 1 (mod m).
    // Choose m = (p-1)*(q-1) for small primes where gcd(e,m)=1.
    // p=1021, q=1031 (both prime, neither divides e=65537).
    // phi = 1020 * 1030 = 1050600.
    // d = 65537^{-1} mod 1050600.
    arm_asm::detail::BigInt<1> m{};
    m.d[0] = 1050600U;
    const auto d = arm_asm::detail::small_e_modinv(m);
    // Verify e * d mod m == 1.
    const __uint128_t prod = static_cast<__uint128_t>(arm_asm::detail::rsa_public_exponent) * d.d[0]; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    const uint64_t rem = static_cast<uint64_t>(prod % 1050600U);
    EXPECT_EQ(rem, 1U);
}

TEST_F(SmallEModinvTests, FailsWhenEDividesM) {
    // m = 2 * 65537 → e | m → no inverse.
    arm_asm::detail::BigInt<1> m{};
    m.d[0] = 2U * arm_asm::detail::rsa_public_exponent;
    const auto d = arm_asm::detail::small_e_modinv(m);
    EXPECT_TRUE(arm_asm::detail::bigint_is_zero(d));
}


// ---------------------------------------------------------------------------
// Miller-Rabin tests
// ---------------------------------------------------------------------------

class MillerRabinTests : public ::testing::Test {};

TEST_F(MillerRabinTests, RejectsTinyComposites) {
    arm_asm::detail::BigInt<1> n{};

    n.d[0] = 9U;   // 3^2
    EXPECT_FALSE(arm_asm::detail::miller_rabin_is_prime(n, miller_rabin_rounds_for(64)));

    n.d[0] = 15U;  // 3*5
    EXPECT_FALSE(arm_asm::detail::miller_rabin_is_prime(n, miller_rabin_rounds_for(64)));

    n.d[0] = 77U;  // 7*11
    EXPECT_FALSE(arm_asm::detail::miller_rabin_is_prime(n, miller_rabin_rounds_for(64)));

    n.d[0] = 561U; // first Carmichael number
    EXPECT_FALSE(arm_asm::detail::miller_rabin_is_prime(n, miller_rabin_rounds_for(64)));
}

TEST_F(MillerRabinTests, AcceptsKnownPrimes) {
    arm_asm::detail::BigInt<1> n{};

    n.d[0] = 7U;
    EXPECT_TRUE(arm_asm::detail::miller_rabin_is_prime(n, miller_rabin_rounds_for(64)));

    n.d[0] = 97U;
    EXPECT_TRUE(arm_asm::detail::miller_rabin_is_prime(n, miller_rabin_rounds_for(64)));

    n.d[0] = 65537U;  // e itself is prime
    EXPECT_TRUE(arm_asm::detail::miller_rabin_is_prime(n, miller_rabin_rounds_for(64)));

    // A large 64-bit prime.
    n.d[0] = 0xFFFFFFFFFFFFFFC5ULL;  // 2^64 - 59 (prime)
    EXPECT_TRUE(arm_asm::detail::miller_rabin_is_prime(n, miller_rabin_rounds_for(64)));
}

TEST_F(MillerRabinTests, UsesFipsRoundCountsForSupportedRsaPrimeSizes) {
    EXPECT_EQ(miller_rabin_rounds_for(rsa_1024_bits / 2U), 5U);
    EXPECT_EQ(miller_rabin_rounds_for(rsa_2048_bits / 2U), 5U);
    EXPECT_EQ(miller_rabin_rounds_for(rsa_3072_bits / 2U), 4U);
    EXPECT_EQ(miller_rabin_rounds_for(4096U / 2U), 4U);

    // Keep larger-than-supported primes on the strongest supported count instead of reducing rounds.
    EXPECT_EQ(miller_rabin_rounds_for(4096U), 4U);
}


// ---------------------------------------------------------------------------
// Key generation tests
// ---------------------------------------------------------------------------

class RsaKeygenTests : public ::testing::Test {
protected:
    void SetUp() override {
        ASSERT_EQ(psa_crypto_init(), PSA_SUCCESS);
    }
};

TEST_F(RsaKeygenTests, GenerateAndParseKeyDer1024) {
    // Generate a 1024-bit key (NW=16).
    constexpr std::size_t NW = 16U;
    constexpr std::size_t modulus_bits = rsa_1024_bits;

    std::array<uint8_t, rsa_1024_bits> der_buf{};
    std::size_t der_len = 0;
    ASSERT_TRUE(arm_asm::detail::rsa_generate_key_der<NW>(
        modulus_bits, der_buf.data(), der_buf.size(), &der_len));
    EXPECT_GT(der_len, 0U);

    // Parse it.
    arm_asm::detail::RsaPrivateKeyComponents priv{};
    ASSERT_TRUE(arm_asm::detail::rsa_parse_private_key_der(der_buf.data(), der_len, priv));

    // n should be 128 bytes (1024-bit).
    EXPECT_EQ(priv.n_len, 128U);
    // e should decode to 65537.
    ASSERT_EQ(priv.e_len, 3U);
    const uint32_t e_val = (static_cast<uint32_t>(priv.e[0]) << 16U) // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
                         | (static_cast<uint32_t>(priv.e[1]) << 8U)  // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
                         |  static_cast<uint32_t>(priv.e[2]);         // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    EXPECT_EQ(e_val, 65537U);
}

TEST_F(RsaKeygenTests, RoundTripEncryptDecrypt1024) {
    // Generate a 1024-bit key pair and exercise encrypt+decrypt.
    constexpr std::size_t NW = 16U;
    constexpr std::size_t k  = 128U;  // key bytes
    constexpr std::size_t modulus_bits = rsa_1024_bits;

    std::array<uint8_t, rsa_1024_bits> der_buf{};
    std::size_t der_len = 0;
    ASSERT_TRUE(arm_asm::detail::rsa_generate_key_der<NW>(
        modulus_bits, der_buf.data(), der_buf.size(), &der_len));

    arm_asm::detail::RsaPrivateKeyComponents priv{};
    ASSERT_TRUE(arm_asm::detail::rsa_parse_private_key_der(der_buf.data(), der_len, priv));

    // Plaintext = 42 (big-endian, 128 bytes).
    std::array<uint8_t, k> m_in{};
    m_in[k - 1U] = 42U;

    // RSA public op: c = m^e mod n.
    std::array<uint8_t, k> c{};
    arm_asm::detail::rsa_public_op<NW>(
        m_in.data(), k,
        priv.n, priv.n_len,
        priv.e, priv.e_len,
        c.data());

    // RSA private op: m' = c^d mod n (CRT).
    std::array<uint8_t, k> m_out{};
    arm_asm::detail::rsa_private_op<NW>(
        c.data(), k,
        priv.p,    priv.p_len,
        priv.q,    priv.q_len,
        priv.dp,   priv.dp_len,
        priv.dq,   priv.dq_len,
        priv.qinv, priv.qinv_len,
        m_out.data());

    EXPECT_EQ(std::memcmp(m_in.data(), m_out.data(), k), 0)
        << "RSA round-trip failed with self-generated key";
}

TEST_F(RsaKeygenTests, OaepRoundTrip1024) {
    // Generate key, OAEP-encode, RSA-encrypt, RSA-decrypt, OAEP-decode.
    constexpr std::size_t NW = 16U;
    constexpr std::size_t k  = 128U;
    constexpr std::size_t modulus_bits = rsa_1024_bits;

    std::array<uint8_t, rsa_1024_bits> der_buf{};
    std::size_t der_len = 0;
    ASSERT_TRUE(arm_asm::detail::rsa_generate_key_der<NW>(
        modulus_bits, der_buf.data(), der_buf.size(), &der_len));

    arm_asm::detail::RsaPrivateKeyComponents priv{};
    ASSERT_TRUE(arm_asm::detail::rsa_parse_private_key_der(der_buf.data(), der_len, priv));

    const std::array<uint8_t, 8> pt = {0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48};  // "ABCDEFGH"

    // OAEP encode.
    std::array<uint8_t, arm_asm::detail::oaep_hash_len> seed{};
    arm_asm::detail::generate_random_bytes(seed.data(), seed.size());
    std::array<uint8_t, k> em{};
    ASSERT_TRUE(arm_asm::detail::oaep_encode(
        pt.data(), pt.size(), nullptr, 0, seed.data(), k, em.data()));

    // RSA encrypt.
    std::array<uint8_t, k> ct{};
    arm_asm::detail::rsa_public_op<NW>(em.data(), k, priv.n, priv.n_len, priv.e, priv.e_len, ct.data());

    // RSA decrypt.
    std::array<uint8_t, k> em_dec{};
    arm_asm::detail::rsa_private_op<NW>(
        ct.data(), k,
        priv.p, priv.p_len, priv.q, priv.q_len,
        priv.dp, priv.dp_len, priv.dq, priv.dq_len,
        priv.qinv, priv.qinv_len,
        em_dec.data());

    // OAEP decode.
    std::array<uint8_t, k> pt_out{};
    std::size_t pt_out_len = 0;
    ASSERT_TRUE(arm_asm::detail::oaep_decode(
        em_dec.data(), k, nullptr, 0, pt_out.data(), pt_out.size(), &pt_out_len));

    EXPECT_EQ(pt_out_len, pt.size());
    EXPECT_EQ(std::memcmp(pt_out.data(), pt.data(), pt.size()), 0);
}

TEST_F(RsaKeygenTests, PsaCanImportOurGeneratedKey) {
    // Generate a key, PSA imports it, verifies it works for OAEP.
    constexpr std::size_t NW = 16U;
    constexpr std::size_t k  = 128U;
    constexpr std::size_t modulus_bits = rsa_1024_bits;

    std::array<uint8_t, rsa_1024_bits> der_buf{};
    std::size_t der_len = 0;
    ASSERT_TRUE(arm_asm::detail::rsa_generate_key_der<NW>(
        modulus_bits, der_buf.data(), der_buf.size(), &der_len));

    // Derive SubjectPublicKeyInfo DER (for our own ops) and PKCS#1 RSAPublicKey (for PSA).
    std::array<uint8_t, 550> pub_der_buf{}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    std::size_t pub_der_len = 0;
    ASSERT_TRUE(arm_asm::detail::rsa_derive_public_key_der(
        der_buf.data(), der_len,
        pub_der_buf.data(), pub_der_buf.size(), &pub_der_len));

    // PKCS#1 RSAPublicKey DER for PSA import (PSA_KEY_TYPE_RSA_PUBLIC_KEY).
    arm_asm::detail::RsaPrivateKeyComponents priv2{};
    ASSERT_TRUE(arm_asm::detail::rsa_parse_private_key_der(der_buf.data(), der_len, priv2));
    std::array<uint8_t, 550> pkcs1_pub_buf{}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    std::size_t pkcs1_pub_len = 0;
    ASSERT_TRUE(arm_asm::detail::rsa_encode_pkcs1_pubkey_der(
        priv2.n, priv2.n_len, priv2.e, priv2.e_len,
        pkcs1_pub_buf.data(), pkcs1_pub_buf.size(), &pkcs1_pub_len));

    // PSA import private key.
    psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attrs, PSA_KEY_TYPE_RSA_KEY_PAIR);
    psa_set_key_bits(&attrs, static_cast<psa_key_bits_t>(modulus_bits));
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_DECRYPT | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attrs, PSA_ALG_RSA_OAEP(PSA_ALG_SHA_384));

    mbedtls_svc_key_id_t psa_id = MBEDTLS_SVC_KEY_ID_INIT;
    ASSERT_EQ(psa_import_key(&attrs, der_buf.data(), der_len, &psa_id), PSA_SUCCESS)
        << "PSA failed to import our generated private key DER";

    // PSA encrypt via public key (don't specify bits — let PSA infer from DER).
    psa_key_attributes_t pub_attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&pub_attrs, PSA_KEY_TYPE_RSA_PUBLIC_KEY);
    psa_set_key_usage_flags(&pub_attrs, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&pub_attrs, PSA_ALG_RSA_OAEP(PSA_ALG_SHA_384));

    mbedtls_svc_key_id_t pub_id = MBEDTLS_SVC_KEY_ID_INIT;
    ASSERT_EQ(psa_import_key(&pub_attrs, pkcs1_pub_buf.data(), pkcs1_pub_len, &pub_id), PSA_SUCCESS);

    const std::array<uint8_t, 8> pt = {1, 2, 3, 4, 5, 6, 7, 8};
    std::array<uint8_t, k> ct{};
    std::size_t ct_len = 0;
    ASSERT_EQ(psa_asymmetric_encrypt(pub_id, PSA_ALG_RSA_OAEP(PSA_ALG_SHA_384),
                                      pt.data(), pt.size(), nullptr, 0,
                                      ct.data(), ct.size(), &ct_len), PSA_SUCCESS);
    psa_destroy_key(pub_id);

    // PSA decrypt.
    std::array<uint8_t, k> pt_out{};
    std::size_t pt_out_len = 0;
    ASSERT_EQ(psa_asymmetric_decrypt(psa_id, PSA_ALG_RSA_OAEP(PSA_ALG_SHA_384),
                                      ct.data(), ct_len, nullptr, 0,
                                      pt_out.data(), pt_out.size(), &pt_out_len), PSA_SUCCESS);
    psa_destroy_key(psa_id);

    EXPECT_EQ(pt_out_len, pt.size());
    EXPECT_EQ(std::memcmp(pt_out.data(), pt.data(), pt.size()), 0);
}

#endif  // SAFE_CRYPTO_ARM_ASM_AVAILABLE
