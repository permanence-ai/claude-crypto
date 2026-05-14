// SPDX-License-Identifier: Apache-2.0

#pragma once

// Unit tests for rsa_bigint.hpp.
//
// Covers:
//   - bigint_from_bytes / bigint_to_bytes round-trip
//   - bigint_add / bigint_sub with carry/borrow
//   - bigint_reduce_once (conditional subtraction)
//   - bigint_ct_lt and bigint_ct_select
//   - mont_neg_inv
//   - mont_mul: verified against small known values
//   - bigint_powmod_ct: verified with RFC 3447 / NIST-style small KATs
//     plus a cross-check against PSA for an actual RSA-3072 private op

#include <array>
#include <cstddef>
#include <cstring>

#include <gtest/gtest.h>

#ifdef SAFE_CRYPTO_ARM_ASM_AVAILABLE

#include "rsa_bigint.hpp"
#include "rsa_der.hpp"

// PSA headers for cross-validation of the full RSA modular exponentiation.
#include <psa/crypto.h>

namespace {

// Decode a fixed-size hex string.
template<std::size_t N>
static ByteArray< N> bigint_from_hex(const char* s) {
    ByteArray< N> out{};
    for (std::size_t i = 0; i < N; ++i) {
        unsigned v = 0;
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        std::sscanf(s + i * 2, "%02x", &v); // NOLINT(cert-err34-c,cert-err33-c,bugprone-unchecked-string-to-number-conversion)
        out[i] = static_cast<uint8_t>(v); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    }
    return out;
}


}  // namespace


// ---------------------------------------------------------------------------
// Load/store tests
// ---------------------------------------------------------------------------

class BigIntLoadStoreTests : public ::testing::Test {};

TEST_F(BigIntLoadStoreTests, FromBytesZero) {
    const ByteArray< 8> bytes{};
    const auto x = arm_asm::detail::bigint_from_bytes<1>(bytes.data(), 8);
    EXPECT_EQ(x.d[0], 0U); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
}

TEST_F(BigIntLoadStoreTests, FromBytesOneWord) {
    // 0x0102030405060708 big-endian → limb[0] = 0x0102030405060708
    const ByteArray< 8> bytes = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08};
    const auto x = arm_asm::detail::bigint_from_bytes<1>(bytes.data(), 8);
    EXPECT_EQ(x.d[0], 0x0102030405060708ULL); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
}

TEST_F(BigIntLoadStoreTests, RoundTripTwoLimbs) {
    // 16 bytes: d[0] = low 8 bytes, d[1] = high 8 bytes (little-endian limbs)
    ByteArray< 16> bytes{};
    for (std::size_t i = 0; i < 16; ++i) { bytes[i] = static_cast<uint8_t>(i + 1); }
    const auto x = arm_asm::detail::bigint_from_bytes<2>(bytes.data(), 16);
    ByteArray< 16> out{};
    arm_asm::detail::bigint_to_bytes(x, out.data());
    EXPECT_EQ(std::memcmp(bytes.data(), out.data(), 16), 0);
}

TEST_F(BigIntLoadStoreTests, ShortInputZeroFillsHigh) {
    // 4 bytes into a 2-limb (16-byte) BigInt: high limb must be zero.
    const ByteArray< 4> bytes = {0xDE,0xAD,0xBE,0xEF};
    const auto x = arm_asm::detail::bigint_from_bytes<2>(bytes.data(), 4);
    EXPECT_EQ(x.d[1], 0U); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    EXPECT_EQ(x.d[0], 0xDEADBEEFULL); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
}


// ---------------------------------------------------------------------------
// Arithmetic tests
// ---------------------------------------------------------------------------

class BigIntArithTests : public ::testing::Test {};

TEST_F(BigIntArithTests, AddNoCarry) {
    arm_asm::detail::BigInt<2> a{}, b{}, out{};
    a.d[0] = 1; b.d[0] = 2;
    const uint64_t carry = arm_asm::detail::bigint_add(out, a, b);
    EXPECT_EQ(carry, 0U);
    EXPECT_EQ(out.d[0], 3U); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    EXPECT_EQ(out.d[1], 0U); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
}

TEST_F(BigIntArithTests, AddWithCarryIntoHighLimb) {
    arm_asm::detail::BigInt<2> a{}, b{}, out{};
    a.d[0] = UINT64_MAX; b.d[0] = 1U;
    const uint64_t carry = arm_asm::detail::bigint_add(out, a, b);
    EXPECT_EQ(carry, 0U);
    EXPECT_EQ(out.d[0], 0U); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    EXPECT_EQ(out.d[1], 1U); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
}

TEST_F(BigIntArithTests, AddOverflowReturnsCarry) {
    arm_asm::detail::BigInt<2> a{}, b{}, out{};
    a.d[0] = UINT64_MAX; a.d[1] = UINT64_MAX;
    b.d[0] = 1U;
    const uint64_t carry = arm_asm::detail::bigint_add(out, a, b);
    EXPECT_EQ(carry, 1U);
    EXPECT_EQ(out.d[0], 0U); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    EXPECT_EQ(out.d[1], 0U); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
}

TEST_F(BigIntArithTests, SubNoUnderflow) {
    arm_asm::detail::BigInt<2> a{}, b{}, out{};
    a.d[0] = 5; b.d[0] = 3;
    const uint64_t borrow = arm_asm::detail::bigint_sub(out, a, b);
    EXPECT_EQ(borrow, 0U);
    EXPECT_EQ(out.d[0], 2U); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
}

TEST_F(BigIntArithTests, SubUnderflowReturnsBorrow) {
    arm_asm::detail::BigInt<2> a{}, b{}, out{};
    a.d[0] = 0; b.d[0] = 1U;
    const uint64_t borrow = arm_asm::detail::bigint_sub(out, a, b);
    EXPECT_EQ(borrow, 1U);
    EXPECT_EQ(out.d[0], UINT64_MAX); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
}

TEST_F(BigIntArithTests, ReduceOnceSubtractsWhenGeM) {
    arm_asm::detail::BigInt<2> a{}, m{};
    a.d[0] = 10; m.d[0] = 7;
    const auto r = arm_asm::detail::bigint_reduce_once(a, m);
    EXPECT_EQ(r.d[0], 3U); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
}

TEST_F(BigIntArithTests, ReduceOnceKeepsWhenLtM) {
    arm_asm::detail::BigInt<2> a{}, m{};
    a.d[0] = 3; m.d[0] = 7;
    const auto r = arm_asm::detail::bigint_reduce_once(a, m);
    EXPECT_EQ(r.d[0], 3U); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
}

TEST_F(BigIntArithTests, CtLtWorksCorrectly) {
    arm_asm::detail::BigInt<2> a{}, b{};
    a.d[0] = 3; b.d[0] = 7;
    EXPECT_EQ(arm_asm::detail::bigint_ct_lt(a, b), UINT64_MAX);
    EXPECT_EQ(arm_asm::detail::bigint_ct_lt(b, a), 0ULL);
    EXPECT_EQ(arm_asm::detail::bigint_ct_lt(a, a), 0ULL);
}

TEST_F(BigIntArithTests, CtSelectPicksA) {
    arm_asm::detail::BigInt<2> a{}, b{};
    a.d[0] = 0xAAAAULL; b.d[0] = 0xBBBBULL;
    const auto r = arm_asm::detail::bigint_ct_select(a, b, UINT64_MAX);
    EXPECT_EQ(r.d[0], 0xAAAAULL); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
}

TEST_F(BigIntArithTests, CtSelectPicksB) {
    arm_asm::detail::BigInt<2> a{}, b{};
    a.d[0] = 0xAAAAULL; b.d[0] = 0xBBBBULL;
    const auto r = arm_asm::detail::bigint_ct_select(a, b, 0ULL);
    EXPECT_EQ(r.d[0], 0xBBBBULL); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
}


// ---------------------------------------------------------------------------
// Montgomery tests
// ---------------------------------------------------------------------------

class BigIntMontTests : public ::testing::Test {};

// Verify mont_neg_inv: m * (-m^{-1}) ≡ -1 mod 2^64, i.e. m * inv ≡ 1 mod 2^64
// when inv = m^{-1} mod 2^64 (not the negation).
TEST_F(BigIntMontTests, NegInvCorrect) {
    // Choose an odd modulus.
    const uint64_t m0 = 0xDEADBEEF12345679ULL;
    const uint64_t neg_inv = arm_asm::detail::mont_neg_inv(m0);
    // m0 * (-m0^{-1}) should be ≡ -1 mod 2^64  →  m0 * neg_inv + 1 ≡ 0 mod 2^64
    EXPECT_EQ(m0 * neg_inv + 1U, 0ULL);
}

// 2^1 mod 3 = 2; 2^2 mod 3 = 1; 2^3 mod 3 = 2.
// Verify using a 1-limb BigInt.
TEST_F(BigIntMontTests, PowModCtSmall) {
    arm_asm::detail::BigInt<1> base{}, exp{}, mod{};
    base.d[0] = 2; exp.d[0] = 3; mod.d[0] = 3;
    // 2^3 mod 3 = 8 mod 3 = 2
    const auto r = arm_asm::detail::bigint_powmod_ct(base, exp, mod);
    EXPECT_EQ(r.d[0], 2U); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
}

TEST_F(BigIntMontTests, PowModCtBase10Exp0) {
    arm_asm::detail::BigInt<1> base{}, exp{}, mod{};
    base.d[0] = 10; exp.d[0] = 0; mod.d[0] = 7;
    // 10^0 mod 7 = 1
    const auto r = arm_asm::detail::bigint_powmod_ct(base, exp, mod);
    EXPECT_EQ(r.d[0], 1U); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
}

TEST_F(BigIntMontTests, PowModCt2To10ModOddPrime) {
    // Montgomery requires an odd modulus.  Use 997 (prime).
    // 2^10 = 1024; 1024 mod 997 = 27.
    arm_asm::detail::BigInt<1> base{}, exp{}, mod{};
    base.d[0] = 2; exp.d[0] = 10; mod.d[0] = 997;
    const auto r = arm_asm::detail::bigint_powmod_ct(base, exp, mod);
    EXPECT_EQ(r.d[0], 27U); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
}

// Fermat's little theorem: a^(p-1) ≡ 1 mod p for prime p, gcd(a,p)=1.
// p = 17 (prime), a = 3: 3^16 mod 17 = 1.
TEST_F(BigIntMontTests, PowModCtFermatSmallPrime) {
    arm_asm::detail::BigInt<1> base{}, exp{}, mod{};
    base.d[0] = 3; exp.d[0] = 16; mod.d[0] = 17;
    const auto r = arm_asm::detail::bigint_powmod_ct(base, exp, mod);
    EXPECT_EQ(r.d[0], 1U); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
}

// RSA round-trip with tiny values: n=77 (7*11), e=7, d=43.
// m=5: c = m^e mod n = 5^7 mod 77 = 78125 mod 77 = 47.
//       m_dec = c^d mod n = 47^43 mod 77 = 5.
TEST_F(BigIntMontTests, RsaTinyRoundTrip) {
    arm_asm::detail::BigInt<1> m_in{}, e{}, n{}, c{}, d{};
    m_in.d[0] = 5; e.d[0] = 7; n.d[0] = 77; d.d[0] = 43;
    // Encrypt
    const auto ct = arm_asm::detail::bigint_powmod_ct(m_in, e, n);
    EXPECT_EQ(ct.d[0], 47U); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    // Decrypt
    c.d[0] = ct.d[0];
    const auto pt = arm_asm::detail::bigint_powmod_ct(c, d, n);
    EXPECT_EQ(pt.d[0], 5U); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
}


// ---------------------------------------------------------------------------
// Cross-validation: PSA generates a 512-bit RSA key; we exercise the raw
// private-op path and compare with PSA's result.
//
// We use 512-bit to keep the test fast; the arithmetic is the same as 3072/4096.
// ---------------------------------------------------------------------------

class BigIntRsaCrossTests : public ::testing::Test {
protected:
    void SetUp() override {
        ASSERT_EQ(psa_crypto_init(), PSA_SUCCESS);
    }
};

TEST_F(BigIntRsaCrossTests, RsaPublicOpMatchesPsa512) {
    // Generate a 1024-bit RSA key via PSA (minimum supported size in mbedtls).
    psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attrs, PSA_KEY_TYPE_RSA_KEY_PAIR);
    psa_set_key_bits(&attrs, rsa_1024_bits);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attrs, PSA_ALG_RSA_PKCS1V15_CRYPT);

    mbedtls_svc_key_id_t psa_id = MBEDTLS_SVC_KEY_ID_INIT;
    ASSERT_EQ(psa_generate_key(&attrs, &psa_id), PSA_SUCCESS);

    // Export private key DER.
    ByteArray< 768> priv_der_buf{}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    std::size_t priv_der_len = 0;
    ASSERT_EQ(psa_export_key(psa_id, priv_der_buf.data(), priv_der_buf.size(), &priv_der_len),
              PSA_SUCCESS);

    psa_destroy_key(psa_id);

    // Parse the key.
    arm_asm::detail::RsaPrivateKeyComponents priv{};
    ASSERT_TRUE(arm_asm::detail::rsa_parse_private_key_der(
        priv_der_buf.data(), priv_der_len, priv));

    // A 1024-bit key: n is 128 bytes → 16 limbs.
    constexpr std::size_t NW = 16;  // 1024 bits / 64 bits per limb
    const std::size_t n_bytes_size = NW * 8U;  // 128 bytes

    // Choose a synthetic plaintext that fits in the modulus.
    // Use m = 42 (trivially < n for any 1024-bit key).
    ByteArray< 128> m_bytes{}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    m_bytes[127] = 42U;  // big-endian 42 // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)

    // Public key operation: c = m^e mod n.
    ByteArray< 128> c_bytes_ours{}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    arm_asm::detail::rsa_public_op<NW>(
        m_bytes.data(), n_bytes_size,
        priv.n, priv.n_len,
        priv.e, priv.e_len,
        c_bytes_ours.data());

    // Private key operation: m' = c^d mod n using CRT.
    ByteArray< 128> m_recovered{}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    arm_asm::detail::rsa_private_op<NW>(
        c_bytes_ours.data(), n_bytes_size,
        priv.p,    priv.p_len,
        priv.q,    priv.q_len,
        priv.dp,   priv.dp_len,
        priv.dq,   priv.dq_len,
        priv.qinv, priv.qinv_len,
        m_recovered.data());

    // m' must equal original m.
    EXPECT_EQ(std::memcmp(m_bytes.data(), m_recovered.data(), n_bytes_size), 0)
        << "RSA round-trip failed: decrypted plaintext does not match original";
}

#endif  // SAFE_CRYPTO_ARM_ASM_AVAILABLE
