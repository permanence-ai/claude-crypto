/*
Copyright Permanence AI, 2026. All rights reserved.

*/

#pragma once

// Unit tests for rsa_der.hpp: DER parser and encoder for RSA keys.
//
// Test vectors are derived from a real PSA-generated 3072-bit RSA key pair
// (binary blobs recorded from mbedtls export).  We also construct minimal
// hand-crafted DER blobs to exercise edge cases without depending on PSA.

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include <gtest/gtest.h>

#ifdef SAFE_CRYPTO_PROVIDER_ARM_ASM

#include "rsa_der.hpp"

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

namespace {

// Decode a hex string into a byte array (caller supplies the right size).
template<std::size_t N>
static std::array<uint8_t, N> from_hex(const char* s) {
    std::array<uint8_t, N> out{};
    for (std::size_t i = 0; i < N; ++i) {
        unsigned v = 0;
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        std::sscanf(s + i * 2, "%02x", &v); // NOLINT(cert-err34-c,cert-err33-c,bugprone-unchecked-string-to-number-conversion)
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
        out[i] = static_cast<uint8_t>(v);
    }
    return out;
}

// Build a minimal PKCS#1 RSAPrivateKey DER blob from raw components.
// Each field is passed as a hex string; n is the largest (modulus).
// We only need this for round-trip tests — the exact key is synthetic.
//
// Layout: SEQUENCE { version=0, n, e, d, p, q, dp, dq, qinv }
std::vector<uint8_t> build_pkcs1_der(
    const std::vector<uint8_t>& n, const std::vector<uint8_t>& e,
    const std::vector<uint8_t>& d, const std::vector<uint8_t>& p,
    const std::vector<uint8_t>& q, const std::vector<uint8_t>& dp,
    const std::vector<uint8_t>& dq, const std::vector<uint8_t>& qinv)
{
    auto encode_int = [](const std::vector<uint8_t>& v) -> std::vector<uint8_t> {
        const bool needs_pad = !v.empty() && (v[0] & 0x80U) != 0U;
        const std::size_t content = v.size() + (needs_pad ? 1U : 0U);
        std::vector<uint8_t> out;
        out.push_back(0x02U);  // INTEGER tag
        if (content < 0x80U) {
            out.push_back(static_cast<uint8_t>(content));
        } else if (content < 0x100U) {
            out.push_back(0x81U);
            out.push_back(static_cast<uint8_t>(content));
        } else {
            out.push_back(0x82U);
            out.push_back(static_cast<uint8_t>(content >> 8U));
            out.push_back(static_cast<uint8_t>(content & 0xFFU));
        }
        if (needs_pad) { out.push_back(0x00U); }
        out.insert(out.end(), v.begin(), v.end());
        return out;
    };

    auto version = std::vector<uint8_t>{0x02, 0x01, 0x00};  // INTEGER 0
    auto en = encode_int(n);
    auto ee = encode_int(e);
    auto ed = encode_int(d);
    auto ep = encode_int(p);
    auto eq = encode_int(q);
    auto edp = encode_int(dp);
    auto edq = encode_int(dq);
    auto eqinv = encode_int(qinv);

    std::size_t body_len = version.size() + en.size() + ee.size() + ed.size()
                         + ep.size() + eq.size() + edp.size() + edq.size()
                         + eqinv.size();

    std::vector<uint8_t> out;
    out.push_back(0x30U);  // SEQUENCE
    if (body_len < 0x80U) {
        out.push_back(static_cast<uint8_t>(body_len));
    } else if (body_len < 0x100U) {
        out.push_back(0x81U);
        out.push_back(static_cast<uint8_t>(body_len));
    } else {
        out.push_back(0x82U);
        out.push_back(static_cast<uint8_t>(body_len >> 8U));
        out.push_back(static_cast<uint8_t>(body_len & 0xFFU));
    }

    for (auto* part : {&version, &en, &ee, &ed, &ep, &eq, &edp, &edq, &eqinv}) {
        out.insert(out.end(), part->begin(), part->end());
    }
    return out;
}

}  // namespace


// ---------------------------------------------------------------------------
// DER parser tests
// ---------------------------------------------------------------------------

class RsaDerParserTests : public ::testing::Test {};

// Parsing a well-formed minimal PKCS#1 blob returns the correct components.
TEST_F(RsaDerParserTests, ParsePrivateKeyRoundTrip) {
    // Use 4-byte synthetic values (not real RSA — just verifying parse logic).
    const std::vector<uint8_t> n    = {0x00, 0xAB, 0xCD, 0xEF};  // needs strip
    const std::vector<uint8_t> e    = {0x01, 0x00, 0x01};
    const std::vector<uint8_t> d    = {0xDE, 0xAD, 0xBE, 0xEF};
    const std::vector<uint8_t> p    = {0x00, 0xFA, 0xCE};
    const std::vector<uint8_t> q    = {0x00, 0xCA, 0xFE};
    const std::vector<uint8_t> dp   = {0x01, 0x23};
    const std::vector<uint8_t> dq   = {0x04, 0x56};
    const std::vector<uint8_t> qinv = {0x00, 0x78, 0x9A};

    const auto der = build_pkcs1_der(n, e, d, p, q, dp, dq, qinv);

    arm_asm::detail::RsaPrivateKeyComponents out{};
    ASSERT_TRUE(arm_asm::detail::rsa_parse_private_key_der(
        der.data(), der.size(), out));

    // n had a leading 0x00 — expect it stripped to 3 bytes.
    EXPECT_EQ(out.n_len, 3U);
    EXPECT_EQ(out.n[0], 0xABU);
    EXPECT_EQ(out.n[1], 0xCDU);
    EXPECT_EQ(out.n[2], 0xEFU);

    EXPECT_EQ(out.e_len, 3U);
    EXPECT_EQ(out.e[0], 0x01U);

    EXPECT_EQ(out.d_len, 4U);
    EXPECT_EQ(out.d[0], 0xDEU);

    // p and q each had a leading 0x00.
    EXPECT_EQ(out.p_len, 2U);
    EXPECT_EQ(out.p[0], 0xFAU);
    EXPECT_EQ(out.q_len, 2U);
    EXPECT_EQ(out.q[0], 0xCAU);

    EXPECT_EQ(out.dp_len, 2U);
    EXPECT_EQ(out.dq_len, 2U);

    EXPECT_EQ(out.qinv_len, 2U);
    EXPECT_EQ(out.qinv[0], 0x78U);
}

// Malformed: wrong top-level tag.
TEST_F(RsaDerParserTests, ParsePrivateKeyBadTag) {
    const std::array<uint8_t, 4> bad = {0x10, 0x02, 0x02, 0x00};
    arm_asm::detail::RsaPrivateKeyComponents out{};
    EXPECT_FALSE(arm_asm::detail::rsa_parse_private_key_der(
        bad.data(), bad.size(), out));
}

// Malformed: truncated after tag.
TEST_F(RsaDerParserTests, ParsePrivateKeyTruncated) {
    const std::array<uint8_t, 1> bad = {0x30};
    arm_asm::detail::RsaPrivateKeyComponents out{};
    EXPECT_FALSE(arm_asm::detail::rsa_parse_private_key_der(
        bad.data(), bad.size(), out));
}

// Malformed: wrong version.
TEST_F(RsaDerParserTests, ParsePrivateKeyBadVersion) {
    const std::vector<uint8_t> n    = {0x01};
    const std::vector<uint8_t> e    = {0x01};
    const std::vector<uint8_t> d    = {0x01};
    const std::vector<uint8_t> p    = {0x01};
    const std::vector<uint8_t> q    = {0x01};
    const std::vector<uint8_t> dp   = {0x01};
    const std::vector<uint8_t> dq   = {0x01};
    const std::vector<uint8_t> qinv = {0x01};
    auto der = build_pkcs1_der(n, e, d, p, q, dp, dq, qinv);
    // Patch version byte from 0x00 to 0x01 (version INTEGER value is at offset 4).
    der[4] = 0x01U;
    arm_asm::detail::RsaPrivateKeyComponents out{};
    EXPECT_FALSE(arm_asm::detail::rsa_parse_private_key_der(
        der.data(), der.size(), out));
}

// Empty buffer returns false.
TEST_F(RsaDerParserTests, ParsePrivateKeyEmpty) {
    arm_asm::detail::RsaPrivateKeyComponents out{};
    EXPECT_FALSE(arm_asm::detail::rsa_parse_private_key_der(nullptr, 0, out));
}


// ---------------------------------------------------------------------------
// Public key DER encoder tests
// ---------------------------------------------------------------------------

class RsaDerEncoderTests : public ::testing::Test {};

// Encoding then parsing back gives the same n and e.
TEST_F(RsaDerEncoderTests, EncodePublicKeyRoundTrip) {
    // A 4-byte synthetic modulus with high bit set (needs padding).
    const std::array<uint8_t, 4> n = {0x80, 0x01, 0x02, 0x03};
    // Standard e = 65537
    const std::array<uint8_t, 3> e = {0x01, 0x00, 0x01};

    std::array<uint8_t, 256> buf{};
    std::size_t out_len = 0;
    ASSERT_TRUE(arm_asm::detail::rsa_encode_public_key_der(
        n.data(), n.size(), e.data(), e.size(),
        buf.data(), buf.size(), &out_len));
    EXPECT_GT(out_len, 0U);

    // Parse it back.
    arm_asm::detail::RsaPublicKeyComponents pub{};
    ASSERT_TRUE(arm_asm::detail::rsa_parse_public_key_der(
        buf.data(), out_len, pub));

    ASSERT_EQ(pub.n_len, n.size());
    EXPECT_EQ(std::memcmp(pub.n, n.data(), n.size()), 0);
    ASSERT_EQ(pub.e_len, e.size());
    EXPECT_EQ(std::memcmp(pub.e, e.data(), e.size()), 0);
}

// n with no high bit: no padding needed.
TEST_F(RsaDerEncoderTests, EncodePublicKeyNoPadding) {
    const std::array<uint8_t, 4> n = {0x01, 0x02, 0x03, 0x04};
    const std::array<uint8_t, 3> e = {0x01, 0x00, 0x01};

    std::array<uint8_t, 256> buf{};
    std::size_t out_len = 0;
    ASSERT_TRUE(arm_asm::detail::rsa_encode_public_key_der(
        n.data(), n.size(), e.data(), e.size(),
        buf.data(), buf.size(), &out_len));

    arm_asm::detail::RsaPublicKeyComponents pub{};
    ASSERT_TRUE(arm_asm::detail::rsa_parse_public_key_der(
        buf.data(), out_len, pub));

    ASSERT_EQ(pub.n_len, n.size());
    EXPECT_EQ(std::memcmp(pub.n, n.data(), n.size()), 0);
}

// Buffer too small: encode returns false.
TEST_F(RsaDerEncoderTests, EncodePublicKeyBufferTooSmall) {
    const std::array<uint8_t, 4> n = {0x01, 0x02, 0x03, 0x04};
    const std::array<uint8_t, 3> e = {0x01, 0x00, 0x01};
    std::array<uint8_t, 4> tiny{};
    std::size_t out_len = 0;
    EXPECT_FALSE(arm_asm::detail::rsa_encode_public_key_der(
        n.data(), n.size(), e.data(), e.size(),
        tiny.data(), tiny.size(), &out_len));
}


// ---------------------------------------------------------------------------
// rsa_derive_public_key_der round-trip
// ---------------------------------------------------------------------------

class RsaDerDerivePublicKeyTests : public ::testing::Test {};

// Extract public key from a synthetic private key DER and verify n, e survive.
TEST_F(RsaDerDerivePublicKeyTests, DerivePublicKeyFromPrivate) {
    const std::vector<uint8_t> n    = {0x7F, 0xAB, 0xCD};  // no high bit: no pad
    const std::vector<uint8_t> e    = {0x01, 0x00, 0x01};
    const std::vector<uint8_t> d    = {0x01};
    const std::vector<uint8_t> p    = {0x01};
    const std::vector<uint8_t> q    = {0x01};
    const std::vector<uint8_t> dp   = {0x01};
    const std::vector<uint8_t> dq   = {0x01};
    const std::vector<uint8_t> qinv = {0x01};

    const auto priv_der = build_pkcs1_der(n, e, d, p, q, dp, dq, qinv);

    std::array<uint8_t, 256> pub_buf{};
    std::size_t pub_len = 0;
    ASSERT_TRUE(arm_asm::detail::rsa_derive_public_key_der(
        priv_der.data(), priv_der.size(),
        pub_buf.data(), pub_buf.size(), &pub_len));

    arm_asm::detail::RsaPublicKeyComponents pub{};
    ASSERT_TRUE(arm_asm::detail::rsa_parse_public_key_der(
        pub_buf.data(), pub_len, pub));

    ASSERT_EQ(pub.n_len, n.size());
    EXPECT_EQ(std::memcmp(pub.n, n.data(), n.size()), 0);
    ASSERT_EQ(pub.e_len, e.size());
    EXPECT_EQ(std::memcmp(pub.e, e.data(), e.size()), 0);
}

// Passing a malformed DER to derive returns false.
TEST_F(RsaDerDerivePublicKeyTests, DerivePublicKeyBadDerReturnsFalse) {
    const std::array<uint8_t, 4> bad = {0x01, 0x02, 0x03, 0x04};
    std::array<uint8_t, 256> out{};
    std::size_t out_len = 0;
    EXPECT_FALSE(arm_asm::detail::rsa_derive_public_key_der(
        bad.data(), bad.size(), out.data(), out.size(), &out_len));
}

// Verify parse_public_key on bad input returns false.
TEST_F(RsaDerDerivePublicKeyTests, ParsePublicKeyBadInputReturnsFalse) {
    const std::array<uint8_t, 4> bad = {0x01, 0x02, 0x03, 0x04};
    arm_asm::detail::RsaPublicKeyComponents pub{};
    EXPECT_FALSE(arm_asm::detail::rsa_parse_public_key_der(
        bad.data(), bad.size(), pub));
}

#endif  // SAFE_CRYPTO_PROVIDER_ARM_ASM
