/*
Copyright Permanence AI, 2026. All rights reserved.

*/

#pragma once

// P-256 (secp256r1) elliptic curve point arithmetic.
//
// Points are in Jacobian projective coordinates: (X:Y:Z) represents
// the affine point (X/Z², Y/Z³).  The point at infinity has Z=0.
//
// Curve equation: y² = x³ − 3x + b  (over GF(p256))
// where b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
//
// P-256 generator:
//   Gx = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
//   Gy = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
//
// Group order n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
//
// Scalar multiplication uses a constant-time left-to-right double-and-add
// (Montgomery ladder variant): processes bits MSB→LSB, always performing
// both a double and an add, selecting via constant-time swap.
//
// Key format (PSA raw private key): big-endian 32-byte scalar.
// Key format (PSA uncompressed public key): 0x04 || big-endian 32-byte x || 32-byte y.

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "p256_field.hpp"


namespace arm_asm::detail {


// -----------------------------------------------------------------------
// Curve constants.
// -----------------------------------------------------------------------

// b coefficient in y² = x³ − 3x + b
static constexpr Fe256 p256_b = {{
    0x3bce3c3e27d2604bULL,
    0x651d06b0cc53b0f6ULL,
    0xb3ebbd55769886bcULL,
    0x5ac635d8aa3a93e7ULL,
}};

// Generator point (affine).
static constexpr Fe256 p256_Gx = {{
    0xf4a13945d898c296ULL,
    0x77037d812deb33a0ULL,
    0xf8bce6e563a440f2ULL,
    0x6b17d1f2e12c4247ULL,
}};
static constexpr Fe256 p256_Gy = {{
    0xcbb6406837bf51f5ULL,
    0x2bce33576b315eceULL,
    0x8ee7eb4a7c0f9e16ULL,
    0x4fe342e2fe1a7f9bULL,
}};

// Group order n.
static constexpr uint64_t p256_n[4] = { // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    0xf3b9cac2fc632551ULL,
    0xbce6faada7179e84ULL,
    0xffffffffffffffffULL,
    0xffffffff00000000ULL,
};


// -----------------------------------------------------------------------
// Jacobian point and affine point.
// -----------------------------------------------------------------------

struct P256Point {
    Fe256 X;
    Fe256 Y;
    Fe256 Z;
};

struct P256AffinePoint {
    Fe256 X;
    Fe256 Y;
};

static constexpr P256Point p256_identity = {
    .X = fe256_zero,
    .Y = fe256_one,
    .Z = fe256_zero,
};

[[nodiscard]]
static inline auto p256_point_is_identity(const P256Point& p) noexcept -> bool {
    return fe256_is_zero(p.Z);
}

// Validate an uncompressed P-256 public key (x, y already loaded as field elements).
// Checks: x < p, y < p, (x,y) != (0,0), y² == x³ - 3x + b mod p.
[[nodiscard]]
static inline auto p256_validate_public_point(const Fe256& x, const Fe256& y) noexcept -> bool {
    // Reject coordinates >= p (fe256_sub_p returns borrow=1 iff a < p).
    Fe256 tmp{};
    if (fe256_sub_p(x, tmp) == 0U) { return false; }
    if (fe256_sub_p(y, tmp) == 0U) { return false; }
    // Reject (0,0) — the point at infinity in affine form.
    if (fe256_is_zero(x) && fe256_is_zero(y)) { return false; }
    // On-curve check: y² == x³ - 3x + b  (a = -3 for P-256).
    const Fe256 y2   = fe256_sqr(y);
    const Fe256 x3   = fe256_mul(fe256_sqr(x), x);
    const Fe256 x3_b = fe256_add(x3, p256_b);
    // Subtract 3x: compute 3x = x+x+x, then x³ + b - 3x.
    const Fe256 x2   = fe256_add(x, x);
    const Fe256 x3x  = fe256_add(x2, x);
    const Fe256 rhs  = fe256_sub(x3_b, x3x);
    return fe256_equal(y2, rhs);
}


// -----------------------------------------------------------------------
// Constant-time conditional swap of two points.
// -----------------------------------------------------------------------

static inline void p256_ct_swap(P256Point& a, P256Point& b, uint64_t swap) noexcept {
    const uint64_t mask = 0U - swap;
    for (int i = 0; i < 4; ++i) {
        const uint64_t tx = (a.X.v[i] ^ b.X.v[i]) & mask;
        a.X.v[i] ^= tx; b.X.v[i] ^= tx;
        const uint64_t ty = (a.Y.v[i] ^ b.Y.v[i]) & mask;
        a.Y.v[i] ^= ty; b.Y.v[i] ^= ty;
        const uint64_t tz = (a.Z.v[i] ^ b.Z.v[i]) & mask;
        a.Z.v[i] ^= tz; b.Z.v[i] ^= tz;
    }
}


// -----------------------------------------------------------------------
// Point doubling in Jacobian coordinates.
// Algorithm: "dbl-2001-b" from https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html
//   delta = Z1^2
//   gamma = Y1^2
//   beta  = X1 * gamma
//   alpha = 3 * (X1 − delta) * (X1 + delta)
//   X3    = alpha^2 − 8*beta
//   Z3    = (Y1 + Z1)^2 − gamma − delta
//   Y3    = alpha * (4*beta − X3) − 8 * gamma^2
// Uses a=−3 via alpha = 3*(X1−delta)*(X1+delta).
// -----------------------------------------------------------------------

[[nodiscard]]
static inline auto p256_point_double(const P256Point& p) noexcept -> P256Point {
    if (p256_point_is_identity(p)) { return p; }

    const Fe256 delta = fe256_sqr(p.Z);
    const Fe256 gamma = fe256_sqr(p.Y);
    const Fe256 beta  = fe256_mul(p.X, gamma);

    // alpha = 3*(X−delta)*(X+delta)
    const Fe256 xmd  = fe256_sub(p.X, delta);
    const Fe256 xpd  = fe256_add(p.X, delta);
    const Fe256 xmxp = fe256_mul(xmd, xpd);
    const Fe256 alpha = fe256_add(fe256_add(xmxp, xmxp), xmxp);  // 3*

    // X3 = alpha^2 − 8*beta
    const Fe256 beta4 = fe256_add(fe256_add(beta, beta), fe256_add(beta, beta));
    const Fe256 beta8 = fe256_add(beta4, beta4);
    const Fe256 x3   = fe256_sub(fe256_sqr(alpha), beta8);

    // Z3 = (Y+Z)^2 − gamma − delta
    const Fe256 z3 = fe256_sub(fe256_sub(fe256_sqr(fe256_add(p.Y, p.Z)), gamma), delta);

    // Y3 = alpha*(4*beta − X3) − 8*gamma^2
    const Fe256 gsq    = fe256_sqr(gamma);
    const Fe256 gsq2   = fe256_add(gsq, gsq);
    const Fe256 gsq4   = fe256_add(gsq2, gsq2);
    const Fe256 gamma8 = fe256_add(gsq4, gsq4);
    const Fe256 y3 = fe256_sub(fe256_mul(alpha, fe256_sub(beta4, x3)), gamma8);

    return P256Point{
        .X = x3,
        .Y = y3,
        .Z = z3,
    };
}


// -----------------------------------------------------------------------
// Point addition in Jacobian coordinates (mixed: both full Jacobian).
// Algorithm: "add-2007-bl" from EFD.
//   U1 = X1*Z2^2,  U2 = X2*Z1^2
//   S1 = Y1*Z2^3,  S2 = Y2*Z1^3
//   H  = U2 − U1
//   R  = S2 − S1
//   X3 = R^2 − H^3 − 2*U1*H^2
//   Y3 = R*(U1*H^2 − X3) − S1*H^3
//   Z3 = H*Z1*Z2
// Returns identity when the inputs are the same non-identity point
// (caller must use double in that case, or use the ladder which avoids it).
// -----------------------------------------------------------------------

[[nodiscard]]
static inline auto p256_point_add(const P256Point& p, const P256Point& q) noexcept -> P256Point {
    if (p256_point_is_identity(p)) { return q; }
    if (p256_point_is_identity(q)) { return p; }

    const Fe256 z1sq = fe256_sqr(p.Z);
    const Fe256 z2sq = fe256_sqr(q.Z);
    const Fe256 u1   = fe256_mul(p.X, z2sq);
    const Fe256 u2   = fe256_mul(q.X, z1sq);
    const Fe256 s1   = fe256_mul(p.Y, fe256_mul(q.Z, z2sq));
    const Fe256 s2   = fe256_mul(q.Y, fe256_mul(p.Z, z1sq));
    const Fe256 h    = fe256_sub(u2, u1);
    const Fe256 r    = fe256_sub(s2, s1);

    // Point doubling case: H == 0 and R == 0 means P == Q.
    if (fe256_is_zero(h) && fe256_is_zero(r)) {
        return p256_point_double(p);
    }

    const Fe256 h2   = fe256_sqr(h);
    const Fe256 h3   = fe256_mul(h, h2);
    const Fe256 u1h2 = fe256_mul(u1, h2);
    const Fe256 x3   = fe256_sub(fe256_sub(fe256_sqr(r), h3), fe256_add(u1h2, u1h2));
    const Fe256 y3   = fe256_sub(fe256_mul(r, fe256_sub(u1h2, x3)), fe256_mul(s1, h3));
    const Fe256 z3   = fe256_mul(fe256_mul(h, p.Z), q.Z);

    return P256Point{
        .X = x3,
        .Y = y3,
        .Z = z3,
    };
}


// -----------------------------------------------------------------------
// Mixed Jacobian–affine add: p (Jacobian) + q (affine, Z=1).
// Saves z2sq, s1 (= p.Y * z2sq = p.Y * 1 = p.Y), and z3 simplification.
// add-2008-g cost: 8M + 3S vs 12M + 4S for full Jacobian.
// -----------------------------------------------------------------------

[[nodiscard]]
static inline auto p256_point_add_affine(const P256Point& p, const P256AffinePoint& q) noexcept -> P256Point
{
    if (p256_point_is_identity(p)) {
        return P256Point{.X = q.X, .Y = q.Y, .Z = fe256_one};
    }

    const Fe256 z1sq = fe256_sqr(p.Z);
    const Fe256 u2   = fe256_mul(q.X, z1sq);
    const Fe256 s2   = fe256_mul(q.Y, fe256_mul(p.Z, z1sq));
    const Fe256 h    = fe256_sub(u2, p.X);
    const Fe256 r    = fe256_sub(s2, p.Y);

    if (fe256_is_zero(h) && fe256_is_zero(r)) {
        // p == q: double
        return p256_point_double(p);
    }

    const Fe256 h2   = fe256_sqr(h);
    const Fe256 h3   = fe256_mul(h, h2);
    const Fe256 u1h2 = fe256_mul(p.X, h2);
    const Fe256 x3   = fe256_sub(fe256_sub(fe256_sqr(r), h3), fe256_add(u1h2, u1h2));
    const Fe256 y3   = fe256_sub(fe256_mul(r, fe256_sub(u1h2, x3)), fe256_mul(p.Y, h3));
    const Fe256 z3   = fe256_mul(h, p.Z);

    return P256Point{
        .X = x3,
        .Y = y3,
        .Z = z3,
    };
}


// -----------------------------------------------------------------------
// Precomputed [1..15]*G table for 4-bit fixed-base window.
// -----------------------------------------------------------------------

static constexpr P256AffinePoint p256_G_table[15] = { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    // [1]*G
    {{0xf4a13945d898c296ULL, 0x77037d812deb33a0ULL, 0xf8bce6e563a440f2ULL, 0x6b17d1f2e12c4247ULL}, {0xcbb6406837bf51f5ULL, 0x2bce33576b315eceULL, 0x8ee7eb4a7c0f9e16ULL, 0x4fe342e2fe1a7f9bULL}},
    // [2]*G
    {{0xa60b48fc47669978ULL, 0xc08969e277f21b35ULL, 0x8a52380304b51ac3ULL, 0x7cf27b188d034f7eULL}, {0x9e04b79d227873d1ULL, 0xba7dade63ce98229ULL, 0x293d9ac69f7430dbULL, 0x07775510db8ed040ULL}},
    // [3]*G
    {{0xfb41661bc6e7fd6cULL, 0xe6c6b721efada985ULL, 0xc8f7ef951d4bf165ULL, 0x5ecbe4d1a6330a44ULL}, {0x9a79b127a27d5032ULL, 0xd82ab036384fb83dULL, 0x374b06ce1a64a2ecULL, 0x8734640c4998ff7eULL}},
    // [4]*G
    {{0x509302446b030852ULL, 0x031fe2db785596efULL, 0xa02dde659ee62bd0ULL, 0xe2534a3532d08fbbULL}, {0x5c42c23f184ed8c6ULL, 0x4efc96c3f30ee005ULL, 0x19dfee5fda862d76ULL, 0xe0f1575a4c633cc7ULL}},
    // [5]*G
    {{0x21554a0dc3d033edULL, 0xef8c82fd1f5be524ULL, 0xd784c85608668fdfULL, 0x51590b7a515140d2ULL}, {0xd1d0bb44fda16da4ULL, 0x0d012f00d4d80888ULL, 0x8ae1bf36bf8a7926ULL, 0xe0c17da8904a727dULL}},
    // [6]*G
    {{0xc6b0aae93c2291a9ULL, 0x024c740debb215b4ULL, 0x92d3242cb897dde3ULL, 0xb01a172a76a4602cULL}, {0xfd7c48538fc77fe2ULL, 0x1c00f7701c7e16bdULL, 0x6fec0e2dfba70379ULL, 0xe85c10743237dad5ULL}},
    // [7]*G
    {{0x300628703187b2a3ULL, 0x7ef9f8b8a80fef5bULL, 0x25bb30667c01fb60ULL, 0x8e533b6fa0bf7b46ULL}, {0xc55e1a86c1f400b4ULL, 0x53c73633cb041b21ULL, 0x6d069f83a6f59000ULL, 0x73eb1dbde0331836ULL}},
    // [8]*G
    {{0xb4dd9dc1db6fb393ULL, 0xc1d238980fce97dbULL, 0x4042742d3ab54cadULL, 0x62d9779dbee9b053ULL}, {0xda540a6a0f09957eULL, 0xa2ed51f6bbe76a78ULL, 0x4ff15d771167cee0ULL, 0xad5accbd91e9d824ULL}},
    // [9]*G
    {{0xd79e8a4b90949ee0ULL, 0x9e0acb8c2c6df8b3ULL, 0x878938d51d71f872ULL, 0xea68d7b6fedf0b71ULL}, {0xe85a224a4dd048faULL, 0x4d714feaa4de823fULL, 0x87014a964a8ea0c8ULL, 0x2a2744c972c9fce7ULL}},
    // [10]*G
    {{0x4c36069404c5723fULL, 0x45ca6c471c48306eULL, 0x591214d1ea223fb5ULL, 0xcef66d6b2a3a993eULL}, {0xca34bbaa44af0773ULL, 0x590ded29fe751eeeULL, 0x6e123cdd9d3b4c10ULL, 0x878662a229aaae90ULL}},
    // [11]*G
    {{0x433391d374bc21d1ULL, 0x16742ed0255048bfULL, 0x0638379db0c21cdaULL, 0x3ed113b7883b4c59ULL}, {0xe2f8eefce82a3740ULL, 0x090d04da5e9889daULL, 0x24c843afa4f4c68aULL, 0x9099209accc4c8a2ULL}},
    // [12]*G
    {{0xd500c5ee8624e3c4ULL, 0x79983028b2f82c99ULL, 0x4626537320e5d551ULL, 0x741dd5bda817d95eULL}, {0x1995ff22cd4481d3ULL, 0x8eeb912c35ba5ca7ULL, 0x567383554887b154ULL, 0x0770b46a9c385fdcULL}},
    // [13]*G
    {{0x98e15d9d46072c01ULL, 0x792e284b65ead58aULL, 0x61805df2d85ee2fcULL, 0x177c837ae0ac495aULL}, {0x9c43bbe2efc7bfd8ULL, 0x26ee14c3a1fb4df3ULL, 0xa24091adb40f4e72ULL, 0x63bb58cd4ebea558ULL}},
    // [14]*G
    {{0x5709277324d2920bULL, 0xf126acbe7a069c5eULL, 0x7a76647f4336df3cULL, 0x54e77a001c3862b9ULL}, {0x1ba7c82f60d0b375ULL, 0x7171ea7773509008ULL, 0x42121f8c05a2e7c3ULL, 0xf599f1bb29f43175ULL}},
    // [15]*G
    {{0x63668c63e59b9d5fULL, 0xae03af92de3a0ef1ULL, 0xadfb378999888265ULL, 0xf0454dc6971abae7ULL}, {0x47e59cde0d034f36ULL, 0x2a3b21ce75b5fa3fULL, 0x4e6594e51f9643e6ULL, 0xb5b93ee3592e2d1fULL}},
}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)


// -----------------------------------------------------------------------
// Fixed-base scalar multiplication using 4-bit window: k·G.
// Processes 64 nibbles MSB→LSB: 4 doublings + 1 mixed-affine-add per step.
// scalar is 32-byte big-endian.
// -----------------------------------------------------------------------

[[nodiscard]]
static inline auto p256_scalar_mul_base( // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    const uint8_t scalar[32]) noexcept -> P256Point
{
    P256Point result = p256_identity;

    for (int byte_i = 0; byte_i < 32; ++byte_i) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        const uint8_t byte_val = scalar[byte_i]; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)

        // High nibble first.
        for (int pass = 0; pass < 2; ++pass) {
            // 4 doublings.
            result = p256_point_double(result);
            result = p256_point_double(result);
            result = p256_point_double(result);
            result = p256_point_double(result);

            const auto nibble = static_cast<unsigned>(
                (pass == 0) ? (byte_val >> 4U) : (byte_val & 0x0fU));

            if (nibble != 0U) {
                result = p256_point_add_affine(result, p256_G_table[nibble - 1U]); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
            }
        }
    }
    return result;
}


// -----------------------------------------------------------------------
// Convert Jacobian → affine.
// -----------------------------------------------------------------------

[[nodiscard]]
static inline auto p256_to_affine(const P256Point& p) noexcept -> P256Point {
    if (p256_point_is_identity(p)) { return p; }
    const Fe256 zinv  = fe256_invert(p.Z);
    const Fe256 zinv2 = fe256_sqr(zinv);
    const Fe256 zinv3 = fe256_mul(zinv, zinv2);
    return P256Point{
        .X = fe256_mul(p.X, zinv2),
        .Y = fe256_mul(p.Y, zinv3),
        .Z = fe256_one,
    };
}


// -----------------------------------------------------------------------
// Constant-time scalar multiplication: k·base.
// Algorithm: double-and-add, always-double, conditional add via ct_select.
// The add is guarded with a "has_result" flag so we never add to identity
// on the first non-zero bit (avoiding the P == identity case in point_add).
// scalar is a 256-bit big-endian byte array.
// This leaks the position of the most-significant bit of the scalar.
// For private-key operations (ECDSA, ECDH) scalars are always full 256-bit
// (n is close to 2^256), so in practice all 256 bits are processed and
// no timing variation occurs.
// -----------------------------------------------------------------------

[[nodiscard]]
static inline auto p256_scalar_mul( // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    const P256Point& base, const uint8_t scalar[32]) noexcept -> P256Point
{
    // result accumulates k·base; tmp is base doubled at each step.
    P256Point result = p256_identity;
    P256Point tmp    = base;

    // Process bits LSB → MSB.
    for (int byte_i = 31; byte_i >= 0; --byte_i) {
        const uint8_t byte_val = scalar[byte_i]; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        for (int bit = 0; bit < 8; ++bit) {
            const uint64_t k_bit = (static_cast<uint64_t>(byte_val) >> static_cast<unsigned>(bit)) & 1U;
            // Conditionally add tmp to result.
            const P256Point added = p256_point_add(result, tmp);
            // CT select: if k_bit==1, take added; else take result.
            const uint64_t mask = 0U - k_bit;
            for (int i = 0; i < 4; ++i) {
                result.X.v[i] = (added.X.v[i] & mask) | (result.X.v[i] & ~mask);
                result.Y.v[i] = (added.Y.v[i] & mask) | (result.Y.v[i] & ~mask);
                result.Z.v[i] = (added.Z.v[i] & mask) | (result.Z.v[i] & ~mask);
            }
            tmp = p256_point_double(tmp);
        }
    }
    return result;
}


// -----------------------------------------------------------------------
// Scalar arithmetic mod n (for ECDSA).
// n is not a Solinas prime so we use schoolbook reduction.
// -----------------------------------------------------------------------

// Reduce a 64-byte (512-bit) big-endian value mod n.
// Used to reduce HMAC output to a scalar.
[[nodiscard]]
static inline auto p256_scalar_from_bytes64( // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    const uint8_t b[64]) noexcept -> Fe256
{
    // Load as 16 × uint32_t big-endian.
    uint32_t w[16]; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    for (int i = 0; i < 16; ++i) {
        const int j = 15 - i;
        const uint8_t* p = b + (j * 4); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        w[i] = (static_cast<uint32_t>(p[0]) << 24U) |
               (static_cast<uint32_t>(p[1]) << 16U) |
               (static_cast<uint32_t>(p[2]) <<  8U) |
                static_cast<uint32_t>(p[3]);
    }

    // Reduce mod n using schoolbook long division (n is ~256-bit).
    // We work with a 512-bit value and reduce by subtracting multiples of n.
    // For simplicity, we reduce the high 256 bits first using Barrett-style:
    //   q = floor(A / n),  r = A − q*n
    // Here we use the fact that 2^256 mod n = 2^256 - n < 2^256.
    // Simple approach: repeated subtraction after two-word shift.

    // Represent as 8 uint64_t LE limbs.
    uint64_t acc[8]; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    for (int i = 0; i < 8; ++i) {
        acc[i] = static_cast<uint64_t>(w[2 * i]) | (static_cast<uint64_t>(w[(2 * i) + 1]) << 32U);
    }

    // Reduce top 4 limbs (acc[4..7]) by replacing 2^256 = n + (2^256 - n).
    // At each step: acc -= (acc >> 256) * n, working 64 bits at a time.
    for (int step = 3; step >= 0; --step) {
        const uint64_t hi = acc[step + 4];
        if (hi == 0U) { continue; }
        acc[step + 4] = 0;
        // Subtract hi * n from acc[step..step+4].
        using u128 = unsigned __int128;
        int64_t borrow = 0;
        for (int i = 0; i < 4; ++i) {
            const auto prod = static_cast<u128>(hi) * p256_n[i];
            const int64_t diff = static_cast<int64_t>(acc[step + i])
                - static_cast<int64_t>(static_cast<uint64_t>(prod)) + borrow;
            acc[step + i] = static_cast<uint64_t>(diff);
            borrow = static_cast<int64_t>(static_cast<uint64_t>(prod >> 64U))
                   - (diff < 0 ? 0LL : 0LL);
            borrow = -(static_cast<int64_t>(prod >> 64U) + (diff >> 63));
        }
        acc[step + 4] = static_cast<uint64_t>(static_cast<int64_t>(acc[step + 4]) + borrow);
    }

    Fe256 r{{acc[0], acc[1], acc[2], acc[3]}};

    // Final reduction: subtract n if r >= n.
    Fe256 sub{};
    // Reuse fe256_sub_p style but against n.
    using u128 = unsigned __int128;
    auto t = static_cast<u128>(r.v[0]) - p256_n[0];
    sub.v[0] = static_cast<uint64_t>(t);
    auto borrow = static_cast<uint64_t>(t >> 127U);
    t = static_cast<u128>(r.v[1]) - p256_n[1] - borrow;
    sub.v[1] = static_cast<uint64_t>(t);
    borrow = static_cast<uint64_t>(t >> 127U);
    t = static_cast<u128>(r.v[2]) - p256_n[2] - borrow;
    sub.v[2] = static_cast<uint64_t>(t);
    borrow = static_cast<uint64_t>(t >> 127U);
    t = static_cast<u128>(r.v[3]) - p256_n[3] - borrow;
    sub.v[3] = static_cast<uint64_t>(t);
    borrow = static_cast<uint64_t>(t >> 127U);
    // If borrow == 0, r >= n, use sub; else use r.
    const uint64_t mask = 0U - (1U - borrow);
    return Fe256{{
        (sub.v[0] & mask) | (r.v[0] & ~mask),
        (sub.v[1] & mask) | (r.v[1] & ~mask),
        (sub.v[2] & mask) | (r.v[2] & ~mask),
        (sub.v[3] & mask) | (r.v[3] & ~mask),
    }};
}

// Reduce a 32-byte big-endian scalar mod n.
[[nodiscard]]
static inline auto p256_scalar_from_bytes32( // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    const uint8_t b[32]) noexcept -> Fe256
{
    Fe256 r{};
    for (int i = 0; i < 4; ++i) {
        const uint8_t* p = b + (3 - i) * 8; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        r.v[i] =
            (static_cast<uint64_t>(p[0]) << 56U) | (static_cast<uint64_t>(p[1]) << 48U) |
            (static_cast<uint64_t>(p[2]) << 40U) | (static_cast<uint64_t>(p[3]) << 32U) |
            (static_cast<uint64_t>(p[4]) << 24U) | (static_cast<uint64_t>(p[5]) << 16U) |
            (static_cast<uint64_t>(p[6]) <<  8U) |  static_cast<uint64_t>(p[7]);
    }
    // Subtract n if r >= n.
    using u128 = unsigned __int128;
    Fe256 sub{};
    auto t = static_cast<u128>(r.v[0]) - p256_n[0];
    sub.v[0] = static_cast<uint64_t>(t);
    auto borrow = static_cast<uint64_t>(t >> 127U);
    t = static_cast<u128>(r.v[1]) - p256_n[1] - borrow;
    sub.v[1] = static_cast<uint64_t>(t);
    borrow = static_cast<uint64_t>(t >> 127U);
    t = static_cast<u128>(r.v[2]) - p256_n[2] - borrow;
    sub.v[2] = static_cast<uint64_t>(t);
    borrow = static_cast<uint64_t>(t >> 127U);
    t = static_cast<u128>(r.v[3]) - p256_n[3] - borrow;
    sub.v[3] = static_cast<uint64_t>(t);
    borrow = static_cast<uint64_t>(t >> 127U);
    const uint64_t mask = 0U - (1U - borrow);
    return Fe256{{
        (sub.v[0] & mask) | (r.v[0] & ~mask),
        (sub.v[1] & mask) | (r.v[1] & ~mask),
        (sub.v[2] & mask) | (r.v[2] & ~mask),
        (sub.v[3] & mask) | (r.v[3] & ~mask),
    }};
}

// Scalar mod-n add.
[[nodiscard]]
static inline auto p256_scalar_add( // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    const Fe256& a, const Fe256& b) noexcept -> Fe256
{
    using u128 = unsigned __int128;
    auto t = static_cast<u128>(a.v[0]) + b.v[0];
    Fe256 r{};
    r.v[0] = static_cast<uint64_t>(t);
    t = static_cast<u128>(a.v[1]) + b.v[1] + (t >> 64U);
    r.v[1] = static_cast<uint64_t>(t);
    t = static_cast<u128>(a.v[2]) + b.v[2] + (t >> 64U);
    r.v[2] = static_cast<uint64_t>(t);
    t = static_cast<u128>(a.v[3]) + b.v[3] + (t >> 64U);
    r.v[3] = static_cast<uint64_t>(t);
    const uint64_t overflow = static_cast<uint64_t>(t >> 64U);

    // Subtract n if r >= n or overflowed.
    Fe256 sub{};
    auto s = static_cast<u128>(r.v[0]) - p256_n[0];
    sub.v[0] = static_cast<uint64_t>(s);
    auto borrow = static_cast<uint64_t>(s >> 127U);
    s = static_cast<u128>(r.v[1]) - p256_n[1] - borrow;
    sub.v[1] = static_cast<uint64_t>(s);
    borrow = static_cast<uint64_t>(s >> 127U);
    s = static_cast<u128>(r.v[2]) - p256_n[2] - borrow;
    sub.v[2] = static_cast<uint64_t>(s);
    borrow = static_cast<uint64_t>(s >> 127U);
    s = static_cast<u128>(r.v[3]) - p256_n[3] - borrow;
    sub.v[3] = static_cast<uint64_t>(s);
    borrow = static_cast<uint64_t>(s >> 127U);
    const uint64_t use_sub = overflow | (1U - borrow);
    const uint64_t mask = 0U - use_sub;
    return Fe256{{
        (sub.v[0] & mask) | (r.v[0] & ~mask),
        (sub.v[1] & mask) | (r.v[1] & ~mask),
        (sub.v[2] & mask) | (r.v[2] & ~mask),
        (sub.v[3] & mask) | (r.v[3] & ~mask),
    }};
}

// Montgomery multiplication CIOS: compute a*b*R^{-1} mod n, R = 2^256.
// n_prime = -n[0]^{-1} mod 2^64 = 0xccd1c8aaee00bc4f.
[[nodiscard]]
static inline auto p256_mont_mul_n(const Fe256& a, const Fe256& b) noexcept -> Fe256
{
    using u128 = unsigned __int128;
    constexpr int s = 4;
    constexpr uint64_t n_prime = 0xccd1c8aaee00bc4fULL;

    uint64_t t[s + 2]{}; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    for (int i = 0; i < s; ++i) {
        // Step 1: t += a[i] * b
        uint64_t carry = 0;
        for (int j = 0; j < s; ++j) {
            const u128 tt = static_cast<u128>(a.v[i]) * b.v[j] + t[j] + carry;
            t[j]  = static_cast<uint64_t>(tt);
            carry = static_cast<uint64_t>(tt >> 64U);
        }
        u128 tt = static_cast<u128>(t[s]) + carry;
        t[s]     = static_cast<uint64_t>(tt);
        t[s + 1] = static_cast<uint64_t>(tt >> 64U);

        // Step 2: Montgomery reduction step.
        const uint64_t m = t[0] * n_prime;
        tt = static_cast<u128>(m) * p256_n[0] + t[0];
        carry = static_cast<uint64_t>(tt >> 64U);
        for (int j = 1; j < s; ++j) {
            tt    = static_cast<u128>(m) * p256_n[j] + t[j] + carry;
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

    Fe256 r{{t[0], t[1], t[2], t[3]}};
    const uint64_t overflow = t[s];

    // Conditional subtract n.
    Fe256 sub{};
    auto st = static_cast<u128>(r.v[0]) - p256_n[0];
    sub.v[0] = static_cast<uint64_t>(st);
    auto borrow = static_cast<uint64_t>(st >> 127U);
    st = static_cast<u128>(r.v[1]) - p256_n[1] - borrow;
    sub.v[1] = static_cast<uint64_t>(st);
    borrow = static_cast<uint64_t>(st >> 127U);
    st = static_cast<u128>(r.v[2]) - p256_n[2] - borrow;
    sub.v[2] = static_cast<uint64_t>(st);
    borrow = static_cast<uint64_t>(st >> 127U);
    st = static_cast<u128>(r.v[3]) - p256_n[3] - borrow;
    sub.v[3] = static_cast<uint64_t>(st);
    borrow = static_cast<uint64_t>(st >> 127U);
    const uint64_t use_sub = overflow | (1U - borrow);
    const uint64_t mask = 0U - use_sub;
    return Fe256{{
        (sub.v[0] & mask) | (r.v[0] & ~mask),
        (sub.v[1] & mask) | (r.v[1] & ~mask),
        (sub.v[2] & mask) | (r.v[2] & ~mask),
        (sub.v[3] & mask) | (r.v[3] & ~mask),
    }};
}

// Scalar mod-n multiply: a*b mod n.
// Computed as CIOS(CIOS(a, R^2), b), where R=2^256 and R^2 mod n is precomputed.
// R^2 mod n = 0x66e12d94f3d956202845b2392b6bec594699799c49bd6fa683244c95be79eea2
[[nodiscard]]
static inline auto p256_scalar_mul_mod_n(
    const Fe256& a, const Fe256& b) noexcept -> Fe256
{
    static constexpr Fe256 r2_mod_n = {{
        0x83244c95be79eea2ULL,
        0x4699799c49bd6fa6ULL,
        0x2845b2392b6bec59ULL,
        0x66e12d94f3d95620ULL,
    }};
    // a_mont = a * R mod n = CIOS(a, R^2)
    const Fe256 a_mont = p256_mont_mul_n(a, r2_mod_n);
    // result = a * b mod n = CIOS(a_mont, b)
    return p256_mont_mul_n(a_mont, b);
}

// Scalar mod-n inversion: a^(n-2) mod n.
[[nodiscard]]
static inline auto p256_scalar_invert(const Fe256& a) noexcept -> Fe256 {
    // n-2 big-endian 64-bit limbs:
    // 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63254F
    static constexpr uint64_t nm2[4] = { // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
        0xf3b9cac2fc63254fULL,
        0xbce6faada7179e84ULL,
        0xffffffffffffffffULL,
        0xffffffff00000000ULL,
    };
    Fe256 result{{1ULL, 0ULL, 0ULL, 0ULL}};
    for (int word = 3; word >= 0; --word) {
        for (int bit = 63; bit >= 0; --bit) {
            result = p256_scalar_mul_mod_n(result, result);
            if (((nm2[word] >> static_cast<unsigned>(bit)) & 1U) != 0U) {
                result = p256_scalar_mul_mod_n(result, a);
            }
        }
    }
    return result;
}

// Is scalar zero?
[[nodiscard]]
static inline auto p256_scalar_is_zero(const Fe256& a) noexcept -> bool {
    return (a.v[0] | a.v[1] | a.v[2] | a.v[3]) == 0U;
}


// -----------------------------------------------------------------------
// Key pair generation and public key encoding.
// private_scalar_be: 32-byte big-endian private key (raw scalar, PSA format).
// public_key_uncompressed: 65-byte 0x04||x||y.
// -----------------------------------------------------------------------

static inline void p256_compute_public_key( // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    const uint8_t private_scalar_be[32],
    uint8_t public_key_uncompressed[65]) noexcept
{
    const P256Point pub = p256_to_affine(p256_scalar_mul_base(private_scalar_be));
    public_key_uncompressed[0] = 0x04U;
    fe256_to_bytes(pub.X, public_key_uncompressed + 1);  // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    fe256_to_bytes(pub.Y, public_key_uncompressed + 33); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
}


}  // namespace arm_asm::detail
