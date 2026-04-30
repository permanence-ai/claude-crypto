/*
Copyright Permanence AI, 2026. All rights reserved.

*/

#pragma once

// P-521 (secp521r1) elliptic curve point arithmetic.
//
// Points are in Jacobian projective coordinates: (X:Y:Z) represents
// the affine point (X/Z², Y/Z³).  The point at infinity has Z=0.
//
// Curve equation: y² = x³ − 3x + b  (over GF(p521))
// where b = 0x0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00
//
// P-521 generator:
//   Gx = 0x00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66
//   Gy = 0x011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650
//
// Group order n = 0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409
//
// Key format (PSA raw private key): big-endian 66-byte scalar.
// Key format (PSA uncompressed public key): 0x04 || big-endian 66-byte x || 66-byte y (133 bytes).

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "p521_field.hpp"


namespace arm_asm::detail {


// -----------------------------------------------------------------------
// Curve constants.
// -----------------------------------------------------------------------

static constexpr Fe521 p521_b = {{
    0xef451fd46b503f00ULL,
    0x3573df883d2c34f1ULL,
    0x1652c0bd3bb1bf07ULL,
    0x56193951ec7e937bULL,
    0xb8b489918ef109e1ULL,
    0xa2da725b99b315f3ULL,
    0x929a21a0b68540eeULL,
    0x953eb9618e1c9a1fULL,
    0x0000000000000051ULL,
}};

static constexpr Fe521 p521_Gx = {{
    0xf97e7e31c2e5bd66ULL,
    0x3348b3c1856a429bULL,
    0xfe1dc127a2ffa8deULL,
    0xa14b5e77efe75928ULL,
    0xf828af606b4d3dbaULL,
    0x9c648139053fb521ULL,
    0x9e3ecb662395b442ULL,
    0x858e06b70404e9cdULL,
    0x00000000000000c6ULL,
}};

static constexpr Fe521 p521_Gy = {{
    0x88be94769fd16650ULL,
    0x353c7086a272c240ULL,
    0xc550b9013fad0761ULL,
    0x97ee72995ef42640ULL,
    0x17afbd17273e662cULL,
    0x98f54449579b4468ULL,
    0x5c8a5fb42c7d1bd9ULL,
    0x39296a789a3bc004ULL,
    0x0000000000000118ULL,
}};

// Group order n.
static constexpr uint64_t p521_n[9] = { // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    0xbb6fb71e91386409ULL,
    0x3bb5c9b8899c47aeULL,
    0x7fcc0148f709a5d0ULL,
    0x51868783bf2f966bULL,
    0xfffffffffffffffaULL,
    0xffffffffffffffffULL,
    0xffffffffffffffffULL,
    0xffffffffffffffffULL,
    0x00000000000001ffULL,
};


// -----------------------------------------------------------------------
// Jacobian point.
// -----------------------------------------------------------------------

struct P521Point {
    Fe521 X;
    Fe521 Y;
    Fe521 Z;
};

static constexpr P521Point p521_identity = {
    .X = fe521_zero,
    .Y = fe521_one,
    .Z = fe521_zero,
};

[[nodiscard]]
static inline auto p521_point_is_identity(const P521Point& p) noexcept -> bool {
    return fe521_is_zero(p.Z);
}


// -----------------------------------------------------------------------
// Point doubling (dbl-2001-b, a=−3 curve).
// -----------------------------------------------------------------------

[[nodiscard]]
static inline auto p521_point_double(const P521Point& p) noexcept -> P521Point {
    if (p521_point_is_identity(p)) { return p; }

    const Fe521 delta = fe521_sqr(p.Z);
    const Fe521 gamma = fe521_sqr(p.Y);
    const Fe521 beta  = fe521_mul(p.X, gamma);

    const Fe521 xmd   = fe521_sub(p.X, delta);
    const Fe521 xpd   = fe521_add(p.X, delta);
    const Fe521 xmxp  = fe521_mul(xmd, xpd);
    const Fe521 alpha = fe521_add(fe521_add(xmxp, xmxp), xmxp);

    const Fe521 beta4 = fe521_add(fe521_add(beta, beta), fe521_add(beta, beta));
    const Fe521 beta8 = fe521_add(beta4, beta4);
    const Fe521 x3    = fe521_sub(fe521_sqr(alpha), beta8);

    const Fe521 z3 = fe521_sub(fe521_sub(fe521_sqr(fe521_add(p.Y, p.Z)), gamma), delta);

    const Fe521 gamma2_8 = fe521_add(fe521_sqr(gamma), fe521_sqr(gamma));
    const Fe521 gamma8   = fe521_add(fe521_add(gamma2_8, gamma2_8), fe521_add(gamma2_8, gamma2_8));
    const Fe521 y3 = fe521_sub(fe521_mul(alpha, fe521_sub(beta4, x3)), gamma8);

    return P521Point{
        .X = x3,
        .Y = y3,
        .Z = z3,
    };
}


// -----------------------------------------------------------------------
// Point addition (add-2007-bl, full Jacobian).
// -----------------------------------------------------------------------

[[nodiscard]]
static inline auto p521_point_add(const P521Point& p, const P521Point& q) noexcept -> P521Point {
    if (p521_point_is_identity(p)) { return q; }
    if (p521_point_is_identity(q)) { return p; }

    const Fe521 z1sq = fe521_sqr(p.Z);
    const Fe521 z2sq = fe521_sqr(q.Z);
    const Fe521 u1   = fe521_mul(p.X, z2sq);
    const Fe521 u2   = fe521_mul(q.X, z1sq);
    const Fe521 s1   = fe521_mul(p.Y, fe521_mul(q.Z, z2sq));
    const Fe521 s2   = fe521_mul(q.Y, fe521_mul(p.Z, z1sq));
    const Fe521 h    = fe521_sub(u2, u1);
    const Fe521 r    = fe521_sub(s2, s1);

    if (fe521_is_zero(h) && fe521_is_zero(r)) {
        return p521_point_double(p);
    }

    const Fe521 h2   = fe521_sqr(h);
    const Fe521 h3   = fe521_mul(h, h2);
    const Fe521 u1h2 = fe521_mul(u1, h2);
    const Fe521 x3   = fe521_sub(fe521_sub(fe521_sqr(r), h3), fe521_add(u1h2, u1h2));
    const Fe521 y3   = fe521_sub(fe521_mul(r, fe521_sub(u1h2, x3)), fe521_mul(s1, h3));
    const Fe521 z3   = fe521_mul(fe521_mul(h, p.Z), q.Z);

    return P521Point{
        .X = x3,
        .Y = y3,
        .Z = z3,
    };
}


// -----------------------------------------------------------------------
// Convert Jacobian → affine.
// -----------------------------------------------------------------------

[[nodiscard]]
static inline auto p521_to_affine(const P521Point& p) noexcept -> P521Point {
    if (p521_point_is_identity(p)) { return p; }
    const Fe521 zinv  = fe521_invert(p.Z);
    const Fe521 zinv2 = fe521_sqr(zinv);
    const Fe521 zinv3 = fe521_mul(zinv, zinv2);
    return P521Point{
        .X = fe521_mul(p.X, zinv2),
        .Y = fe521_mul(p.Y, zinv3),
        .Z = fe521_one,
    };
}


// -----------------------------------------------------------------------
// Constant-time scalar multiplication: k·base.
// scalar is a 521-bit big-endian byte array (66 bytes).
// -----------------------------------------------------------------------

[[nodiscard]]
static inline auto p521_scalar_mul( // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    const P521Point& base, const uint8_t scalar[66]) noexcept -> P521Point // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
{
    P521Point result = p521_identity;
    P521Point tmp    = base;

    // Process 65 full bytes (bits 0–519) and the low 9 bits of byte[0].
    // scalar[65] is LSB, scalar[0] is MSB (big-endian).
    // We iterate LSB to MSB: byte 65 down to byte 0, bit 0 to bit 7 per byte,
    // but byte 0 only contributes 1 bit (bit 0, i.e. the 521st bit = bit 520).
    for (int byte_i = 65; byte_i >= 1; --byte_i) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        const uint8_t byte_val = scalar[byte_i]; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        for (int bit = 0; bit < 8; ++bit) {
            const uint64_t k_bit = (static_cast<uint64_t>(byte_val) >> static_cast<unsigned>(bit)) & 1U;
            const P521Point added = p521_point_add(result, tmp);
            const uint64_t mask = 0U - k_bit;
            for (int i = 0; i < 9; ++i) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
                result.X.v[i] = (added.X.v[i] & mask) | (result.X.v[i] & ~mask);
                result.Y.v[i] = (added.Y.v[i] & mask) | (result.Y.v[i] & ~mask);
                result.Z.v[i] = (added.Z.v[i] & mask) | (result.Z.v[i] & ~mask);
            }
            tmp = p521_point_double(tmp);
        }
    }
    // Process the top byte: only 1 bit (bit 0 of scalar[0]).
    {
        const uint64_t k_bit = static_cast<uint64_t>(scalar[0]) & 1U; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        const P521Point added = p521_point_add(result, tmp);
        const uint64_t mask = 0U - k_bit;
        for (int i = 0; i < 9; ++i) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
            result.X.v[i] = (added.X.v[i] & mask) | (result.X.v[i] & ~mask);
            result.Y.v[i] = (added.Y.v[i] & mask) | (result.Y.v[i] & ~mask);
            result.Z.v[i] = (added.Z.v[i] & mask) | (result.Z.v[i] & ~mask);
        }
    }
    return result;
}


// -----------------------------------------------------------------------
// Scalar arithmetic mod n.
// -----------------------------------------------------------------------

[[nodiscard]]
static inline auto p521_scalar_from_bytes66( // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    const uint8_t b[66]) noexcept -> Fe521 // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
{
    // Load as field element, then conditionally subtract n once.
    Fe521 r{};
    for (int i = 0; i < 8; ++i) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        const uint8_t* p = b + (65 - i * 8); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic,cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        r.v[i] =
            (static_cast<uint64_t>(p[-7]) << 56U) | (static_cast<uint64_t>(p[-6]) << 48U) | // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
            (static_cast<uint64_t>(p[-5]) << 40U) | (static_cast<uint64_t>(p[-4]) << 32U) | // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
            (static_cast<uint64_t>(p[-3]) << 24U) | (static_cast<uint64_t>(p[-2]) << 16U) | // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
            (static_cast<uint64_t>(p[-1]) <<  8U) |  static_cast<uint64_t>(p[0]);           // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    }
    r.v[8] = (static_cast<uint64_t>(b[0]) << 8U) | static_cast<uint64_t>(b[1]); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic,cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    r.v[8] &= 0x1ffULL;

    // Conditional subtract n.
    using u128 = unsigned __int128;
    Fe521 sub{};
    auto t = static_cast<u128>(r.v[0]) - p521_n[0];
    sub.v[0] = static_cast<uint64_t>(t);
    auto borrow = static_cast<uint64_t>(t >> 127U);
    t = static_cast<u128>(r.v[1]) - p521_n[1] - borrow;
    sub.v[1] = static_cast<uint64_t>(t);
    borrow = static_cast<uint64_t>(t >> 127U);
    t = static_cast<u128>(r.v[2]) - p521_n[2] - borrow;
    sub.v[2] = static_cast<uint64_t>(t);
    borrow = static_cast<uint64_t>(t >> 127U);
    t = static_cast<u128>(r.v[3]) - p521_n[3] - borrow;
    sub.v[3] = static_cast<uint64_t>(t);
    borrow = static_cast<uint64_t>(t >> 127U);
    t = static_cast<u128>(r.v[4]) - p521_n[4] - borrow;
    sub.v[4] = static_cast<uint64_t>(t);
    borrow = static_cast<uint64_t>(t >> 127U);
    t = static_cast<u128>(r.v[5]) - p521_n[5] - borrow;
    sub.v[5] = static_cast<uint64_t>(t);
    borrow = static_cast<uint64_t>(t >> 127U);
    t = static_cast<u128>(r.v[6]) - p521_n[6] - borrow;
    sub.v[6] = static_cast<uint64_t>(t);
    borrow = static_cast<uint64_t>(t >> 127U);
    t = static_cast<u128>(r.v[7]) - p521_n[7] - borrow;
    sub.v[7] = static_cast<uint64_t>(t);
    borrow = static_cast<uint64_t>(t >> 127U);
    t = static_cast<u128>(r.v[8]) - p521_n[8] - borrow;
    sub.v[8] = static_cast<uint64_t>(t) & 0x1ffULL;
    borrow = static_cast<uint64_t>(t >> 127U);
    const uint64_t mask = 0U - (1U - borrow);
    return Fe521{{
        (sub.v[0] & mask) | (r.v[0] & ~mask),
        (sub.v[1] & mask) | (r.v[1] & ~mask),
        (sub.v[2] & mask) | (r.v[2] & ~mask),
        (sub.v[3] & mask) | (r.v[3] & ~mask),
        (sub.v[4] & mask) | (r.v[4] & ~mask),
        (sub.v[5] & mask) | (r.v[5] & ~mask),
        (sub.v[6] & mask) | (r.v[6] & ~mask),
        (sub.v[7] & mask) | (r.v[7] & ~mask),
        (sub.v[8] & mask) | (r.v[8] & ~mask),
    }};
}

// Load a hash of hlen bytes (< qlen=66) as a scalar: zero-pad on the left to 66 bytes.
[[nodiscard]]
static inline auto p521_scalar_from_bytes66_hash( // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    const uint8_t* hash_be, std::size_t hlen) noexcept -> Fe521
{
    uint8_t padded[66] = {}; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays,cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    const std::size_t qlen = 66; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    if (hlen >= qlen) {
        std::memcpy(padded, hash_be, qlen);
    } else {
        std::memcpy(padded + (qlen - hlen), hash_be, hlen); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    }
    return p521_scalar_from_bytes66(padded);
}

[[nodiscard]]
static inline auto p521_scalar_add( // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    const Fe521& a, const Fe521& b) noexcept -> Fe521
{
    using u128 = unsigned __int128;
    auto t = static_cast<u128>(a.v[0]) + b.v[0];
    Fe521 r{};
    r.v[0] = static_cast<uint64_t>(t);
    t = static_cast<u128>(a.v[1]) + b.v[1] + (t >> 64U);
    r.v[1] = static_cast<uint64_t>(t);
    t = static_cast<u128>(a.v[2]) + b.v[2] + (t >> 64U);
    r.v[2] = static_cast<uint64_t>(t);
    t = static_cast<u128>(a.v[3]) + b.v[3] + (t >> 64U);
    r.v[3] = static_cast<uint64_t>(t);
    t = static_cast<u128>(a.v[4]) + b.v[4] + (t >> 64U);
    r.v[4] = static_cast<uint64_t>(t);
    t = static_cast<u128>(a.v[5]) + b.v[5] + (t >> 64U);
    r.v[5] = static_cast<uint64_t>(t);
    t = static_cast<u128>(a.v[6]) + b.v[6] + (t >> 64U);
    r.v[6] = static_cast<uint64_t>(t);
    t = static_cast<u128>(a.v[7]) + b.v[7] + (t >> 64U);
    r.v[7] = static_cast<uint64_t>(t);
    t = static_cast<u128>(a.v[8]) + b.v[8] + (t >> 64U);
    r.v[8] = static_cast<uint64_t>(t);
    const uint64_t overflow = static_cast<uint64_t>(t >> 64U);

    Fe521 sub{};
    auto s = static_cast<u128>(r.v[0]) - p521_n[0];
    sub.v[0] = static_cast<uint64_t>(s);
    auto borrow = static_cast<uint64_t>(s >> 127U);
    s = static_cast<u128>(r.v[1]) - p521_n[1] - borrow;
    sub.v[1] = static_cast<uint64_t>(s);
    borrow = static_cast<uint64_t>(s >> 127U);
    s = static_cast<u128>(r.v[2]) - p521_n[2] - borrow;
    sub.v[2] = static_cast<uint64_t>(s);
    borrow = static_cast<uint64_t>(s >> 127U);
    s = static_cast<u128>(r.v[3]) - p521_n[3] - borrow;
    sub.v[3] = static_cast<uint64_t>(s);
    borrow = static_cast<uint64_t>(s >> 127U);
    s = static_cast<u128>(r.v[4]) - p521_n[4] - borrow;
    sub.v[4] = static_cast<uint64_t>(s);
    borrow = static_cast<uint64_t>(s >> 127U);
    s = static_cast<u128>(r.v[5]) - p521_n[5] - borrow;
    sub.v[5] = static_cast<uint64_t>(s);
    borrow = static_cast<uint64_t>(s >> 127U);
    s = static_cast<u128>(r.v[6]) - p521_n[6] - borrow;
    sub.v[6] = static_cast<uint64_t>(s);
    borrow = static_cast<uint64_t>(s >> 127U);
    s = static_cast<u128>(r.v[7]) - p521_n[7] - borrow;
    sub.v[7] = static_cast<uint64_t>(s);
    borrow = static_cast<uint64_t>(s >> 127U);
    s = static_cast<u128>(r.v[8]) - p521_n[8] - borrow;
    sub.v[8] = static_cast<uint64_t>(s) & 0x1ffULL;
    borrow = static_cast<uint64_t>(s >> 127U);
    const uint64_t use_sub = overflow | (1U - borrow);
    const uint64_t mask = 0U - use_sub;
    return Fe521{{
        (sub.v[0] & mask) | (r.v[0] & ~mask),
        (sub.v[1] & mask) | (r.v[1] & ~mask),
        (sub.v[2] & mask) | (r.v[2] & ~mask),
        (sub.v[3] & mask) | (r.v[3] & ~mask),
        (sub.v[4] & mask) | (r.v[4] & ~mask),
        (sub.v[5] & mask) | (r.v[5] & ~mask),
        (sub.v[6] & mask) | (r.v[6] & ~mask),
        (sub.v[7] & mask) | (r.v[7] & ~mask),
        (sub.v[8] & mask) | (r.v[8] & ~mask),
    }};
}

// Montgomery CIOS multiplication mod n for P-521.
// Computes a*b*R^{-1} mod n where R = 2^576 (9 × 64-bit limbs).
// n_prime = -n[0]^{-1} mod 2^64 = 0x1d2f5ccd79a995c7
[[nodiscard]]
static inline auto p521_mont_mul_n(const Fe521& a, const Fe521& b) noexcept -> Fe521
{
    using u128 = unsigned __int128;
    constexpr int s = 9; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    constexpr uint64_t n_prime = 0x1d2f5ccd79a995c7ULL;

    uint64_t t[s + 2]{}; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    for (int i = 0; i < s; ++i) {
        uint64_t carry = 0;
        for (int j = 0; j < s; ++j) {
            const u128 tt = static_cast<u128>(a.v[i]) * b.v[j] + t[j] + carry;
            t[j]  = static_cast<uint64_t>(tt);
            carry = static_cast<uint64_t>(tt >> 64U);
        }
        u128 tt = static_cast<u128>(t[s]) + carry;
        t[s]     = static_cast<uint64_t>(tt);
        t[s + 1] = static_cast<uint64_t>(tt >> 64U);

        const uint64_t m = t[0] * n_prime;
        tt = static_cast<u128>(m) * p521_n[0] + t[0];
        carry = static_cast<uint64_t>(tt >> 64U);
        for (int j = 1; j < s; ++j) {
            tt       = static_cast<u128>(m) * p521_n[j] + t[j] + carry;
            t[j - 1] = static_cast<uint64_t>(tt);
            carry    = static_cast<uint64_t>(tt >> 64U);
        }
        tt = static_cast<u128>(t[s]) + carry;
        t[s - 1] = static_cast<uint64_t>(tt);
        carry    = static_cast<uint64_t>(tt >> 64U);
        tt = static_cast<u128>(t[s + 1]) + carry;
        t[s]     = static_cast<uint64_t>(tt);
        t[s + 1] = 0;
    }

    Fe521 r{{t[0], t[1], t[2], t[3], t[4], t[5], t[6], t[7], t[8]}}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    const uint64_t overflow = t[s];

    Fe521 sub{};
    auto st = static_cast<u128>(r.v[0]) - p521_n[0];
    sub.v[0] = static_cast<uint64_t>(st);
    auto borrow = static_cast<uint64_t>(st >> 127U);
    st = static_cast<u128>(r.v[1]) - p521_n[1] - borrow;
    sub.v[1] = static_cast<uint64_t>(st);
    borrow = static_cast<uint64_t>(st >> 127U);
    st = static_cast<u128>(r.v[2]) - p521_n[2] - borrow;
    sub.v[2] = static_cast<uint64_t>(st);
    borrow = static_cast<uint64_t>(st >> 127U);
    st = static_cast<u128>(r.v[3]) - p521_n[3] - borrow;
    sub.v[3] = static_cast<uint64_t>(st);
    borrow = static_cast<uint64_t>(st >> 127U);
    st = static_cast<u128>(r.v[4]) - p521_n[4] - borrow;
    sub.v[4] = static_cast<uint64_t>(st);
    borrow = static_cast<uint64_t>(st >> 127U);
    st = static_cast<u128>(r.v[5]) - p521_n[5] - borrow;
    sub.v[5] = static_cast<uint64_t>(st);
    borrow = static_cast<uint64_t>(st >> 127U);
    st = static_cast<u128>(r.v[6]) - p521_n[6] - borrow;
    sub.v[6] = static_cast<uint64_t>(st);
    borrow = static_cast<uint64_t>(st >> 127U);
    st = static_cast<u128>(r.v[7]) - p521_n[7] - borrow;
    sub.v[7] = static_cast<uint64_t>(st);
    borrow = static_cast<uint64_t>(st >> 127U);
    st = static_cast<u128>(r.v[8]) - p521_n[8] - borrow;
    sub.v[8] = static_cast<uint64_t>(st) & 0x1ffULL;
    borrow = static_cast<uint64_t>(st >> 127U);
    const uint64_t use_sub = overflow | (1U - borrow);
    const uint64_t mask = 0U - use_sub;
    return Fe521{{
        (sub.v[0] & mask) | (r.v[0] & ~mask),
        (sub.v[1] & mask) | (r.v[1] & ~mask),
        (sub.v[2] & mask) | (r.v[2] & ~mask),
        (sub.v[3] & mask) | (r.v[3] & ~mask),
        (sub.v[4] & mask) | (r.v[4] & ~mask),
        (sub.v[5] & mask) | (r.v[5] & ~mask),
        (sub.v[6] & mask) | (r.v[6] & ~mask),
        (sub.v[7] & mask) | (r.v[7] & ~mask),
        (sub.v[8] & mask) | (r.v[8] & ~mask),
    }};
}

// Scalar mod-n multiply: a*b mod n.
// R^2 mod n (R=2^576):
[[nodiscard]]
static inline auto p521_scalar_mul_mod_n(
    const Fe521& a, const Fe521& b) noexcept -> Fe521
{
    static constexpr Fe521 r2_mod_n = {{
        0x137cd04dcf15dd04ULL,
        0xf707badce5547ea3ULL,
        0x12a78d38794573ffULL,
        0xd3721ef557f75e06ULL,
        0xdd6e23d82e49c7dbULL,
        0xcff3d142b7756e3eULL,
        0x5bcc6d61a8e567bcULL,
        0x2d8e03d1492d0d45ULL,
        0x000000000000003dULL,
    }};
    const Fe521 a_mont = p521_mont_mul_n(a, r2_mod_n);
    return p521_mont_mul_n(a_mont, b);
}

[[nodiscard]]
static inline auto p521_scalar_invert(const Fe521& a) noexcept -> Fe521 {
    static constexpr uint64_t nm2[9] = { // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
        0xbb6fb71e91386407ULL,
        0x3bb5c9b8899c47aeULL,
        0x7fcc0148f709a5d0ULL,
        0x51868783bf2f966bULL,
        0xfffffffffffffffaULL,
        0xffffffffffffffffULL,
        0xffffffffffffffffULL,
        0xffffffffffffffffULL,
        0x00000000000001ffULL,
    };
    Fe521 result{{1ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL}};
    for (int word = 8; word >= 0; --word) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        const int bits = (word == 8) ? 9 : 64; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        for (int bit = bits - 1; bit >= 0; --bit) {
            result = p521_scalar_mul_mod_n(result, result);
            if (((nm2[word] >> static_cast<unsigned>(bit)) & 1U) != 0U) {
                result = p521_scalar_mul_mod_n(result, a);
            }
        }
    }
    return result;
}

[[nodiscard]]
static inline auto p521_scalar_is_zero(const Fe521& a) noexcept -> bool {
    return (a.v[0] | a.v[1] | a.v[2] | a.v[3] | a.v[4] |
            a.v[5] | a.v[6] | a.v[7] | a.v[8]) == 0U;
}


// -----------------------------------------------------------------------
// Key pair generation and public key encoding.
// -----------------------------------------------------------------------

static inline void p521_compute_public_key( // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    const uint8_t private_scalar_be[66], // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    uint8_t public_key_uncompressed[133]) noexcept // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
{
    const P521Point pub = p521_to_affine(p521_scalar_mul(
        P521Point{.X = p521_Gx, .Y = p521_Gy, .Z = fe521_one},
        private_scalar_be));
    public_key_uncompressed[0] = 0x04U;
    fe521_to_bytes(pub.X, public_key_uncompressed + 1);   // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    fe521_to_bytes(pub.Y, public_key_uncompressed + 67);  // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic,cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
}


}  // namespace arm_asm::detail
