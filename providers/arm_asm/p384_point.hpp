/*
Copyright Permanence AI, 2026. All rights reserved.

*/

#pragma once

// P-384 (secp384r1) elliptic curve point arithmetic.
//
// Points are in Jacobian projective coordinates: (X:Y:Z) represents
// the affine point (X/Z², Y/Z³).  The point at infinity has Z=0.
//
// Curve equation: y² = x³ − 3x + b  (over GF(p384))
// where b = 0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF
//
// P-384 generator:
//   Gx = 0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7
//   Gy = 0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F
//
// Group order n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973
//
// Key format (PSA raw private key): big-endian 48-byte scalar.
// Key format (PSA uncompressed public key): 0x04 || big-endian 48-byte x || 48-byte y.

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "p384_field.hpp"


namespace arm_asm::detail {


// -----------------------------------------------------------------------
// Curve constants.
// -----------------------------------------------------------------------

static constexpr Fe384 p384_b = {{
    0x2a85c8edd3ec2aefULL,
    0xc656398d8a2ed19dULL,
    0x0314088f5013875aULL,
    0x181d9c6efe814112ULL,
    0x988e056be3f82d19ULL,
    0xb3312fa7e23ee7e4ULL,
}};

static constexpr Fe384 p384_Gx = {{
    0x3a545e3872760ab7ULL,
    0x5502f25dbf55296cULL,
    0x59f741e082542a38ULL,
    0x6e1d3b628ba79b98ULL,
    0x8eb1c71ef320ad74ULL,
    0xaa87ca22be8b0537ULL,
}};

static constexpr Fe384 p384_Gy = {{
    0x7a431d7c90ea0e5fULL,
    0x0a60b1ce1d7e819dULL,
    0xe9da3113b5f0b8c0ULL,
    0xf8f41dbd289a147cULL,
    0x5d9e98bf9292dc29ULL,
    0x3617de4a96262c6fULL,
}};

// Group order n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973
static constexpr uint64_t p384_n[6] = { // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    0xecec196accc52973ULL,
    0x581a0db248b0a77aULL,
    0xc7634d81f4372ddfULL,
    0xffffffffffffffffULL,
    0xffffffffffffffffULL,
    0xffffffffffffffffULL,
};


// -----------------------------------------------------------------------
// Jacobian point.
// -----------------------------------------------------------------------

struct P384Point {
    Fe384 X;
    Fe384 Y;
    Fe384 Z;
};

static constexpr P384Point p384_identity = {
    .X = fe384_zero,
    .Y = fe384_one,
    .Z = fe384_zero,
};

[[nodiscard]]
static inline auto p384_point_is_identity(const P384Point& p) noexcept -> bool {
    return fe384_is_zero(p.Z);
}


// -----------------------------------------------------------------------
// Point doubling (dbl-2001-b, a=−3 curve).
// -----------------------------------------------------------------------

[[nodiscard]]
static inline auto p384_point_double(const P384Point& p) noexcept -> P384Point {
    if (p384_point_is_identity(p)) { return p; }

    const Fe384 delta = fe384_sqr(p.Z);
    const Fe384 gamma = fe384_sqr(p.Y);
    const Fe384 beta  = fe384_mul(p.X, gamma);

    const Fe384 xmd   = fe384_sub(p.X, delta);
    const Fe384 xpd   = fe384_add(p.X, delta);
    const Fe384 xmxp  = fe384_mul(xmd, xpd);
    const Fe384 alpha = fe384_add(fe384_add(xmxp, xmxp), xmxp);

    const Fe384 beta4 = fe384_add(fe384_add(beta, beta), fe384_add(beta, beta));
    const Fe384 beta8 = fe384_add(beta4, beta4);
    const Fe384 x3    = fe384_sub(fe384_sqr(alpha), beta8);

    const Fe384 z3 = fe384_sub(fe384_sub(fe384_sqr(fe384_add(p.Y, p.Z)), gamma), delta);

    const Fe384 gamma2_8 = fe384_add(fe384_sqr(gamma), fe384_sqr(gamma));
    const Fe384 gamma8   = fe384_add(fe384_add(gamma2_8, gamma2_8), fe384_add(gamma2_8, gamma2_8));
    const Fe384 y3 = fe384_sub(fe384_mul(alpha, fe384_sub(beta4, x3)), gamma8);

    return P384Point{
        .X = x3,
        .Y = y3,
        .Z = z3,
    };
}


// -----------------------------------------------------------------------
// Point addition (add-2007-bl, full Jacobian).
// -----------------------------------------------------------------------

[[nodiscard]]
static inline auto p384_point_add(const P384Point& p, const P384Point& q) noexcept -> P384Point {
    if (p384_point_is_identity(p)) { return q; }
    if (p384_point_is_identity(q)) { return p; }

    const Fe384 z1sq = fe384_sqr(p.Z);
    const Fe384 z2sq = fe384_sqr(q.Z);
    const Fe384 u1   = fe384_mul(p.X, z2sq);
    const Fe384 u2   = fe384_mul(q.X, z1sq);
    const Fe384 s1   = fe384_mul(p.Y, fe384_mul(q.Z, z2sq));
    const Fe384 s2   = fe384_mul(q.Y, fe384_mul(p.Z, z1sq));
    const Fe384 h    = fe384_sub(u2, u1);
    const Fe384 r    = fe384_sub(s2, s1);

    if (fe384_is_zero(h) && fe384_is_zero(r)) {
        return p384_point_double(p);
    }

    const Fe384 h2   = fe384_sqr(h);
    const Fe384 h3   = fe384_mul(h, h2);
    const Fe384 u1h2 = fe384_mul(u1, h2);
    const Fe384 x3   = fe384_sub(fe384_sub(fe384_sqr(r), h3), fe384_add(u1h2, u1h2));
    const Fe384 y3   = fe384_sub(fe384_mul(r, fe384_sub(u1h2, x3)), fe384_mul(s1, h3));
    const Fe384 z3   = fe384_mul(fe384_mul(h, p.Z), q.Z);

    return P384Point{
        .X = x3,
        .Y = y3,
        .Z = z3,
    };
}


// -----------------------------------------------------------------------
// Convert Jacobian → affine.
// -----------------------------------------------------------------------

[[nodiscard]]
static inline auto p384_to_affine(const P384Point& p) noexcept -> P384Point {
    if (p384_point_is_identity(p)) { return p; }
    const Fe384 zinv  = fe384_invert(p.Z);
    const Fe384 zinv2 = fe384_sqr(zinv);
    const Fe384 zinv3 = fe384_mul(zinv, zinv2);
    return P384Point{
        .X = fe384_mul(p.X, zinv2),
        .Y = fe384_mul(p.Y, zinv3),
        .Z = fe384_one,
    };
}


// -----------------------------------------------------------------------
// Constant-time scalar multiplication: k·base.
// scalar is a 384-bit big-endian byte array (48 bytes).
// -----------------------------------------------------------------------

[[nodiscard]]
static inline auto p384_scalar_mul( // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    const P384Point& base, const uint8_t scalar[48]) noexcept -> P384Point
{
    P384Point result = p384_identity;
    P384Point tmp    = base;

    for (int byte_i = 47; byte_i >= 0; --byte_i) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        const uint8_t byte_val = scalar[byte_i]; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        for (int bit = 0; bit < 8; ++bit) {
            const uint64_t k_bit = (static_cast<uint64_t>(byte_val) >> static_cast<unsigned>(bit)) & 1U;
            const P384Point added = p384_point_add(result, tmp);
            const uint64_t mask = 0U - k_bit;
            for (int i = 0; i < 6; ++i) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
                result.X.v[i] = (added.X.v[i] & mask) | (result.X.v[i] & ~mask);
                result.Y.v[i] = (added.Y.v[i] & mask) | (result.Y.v[i] & ~mask);
                result.Z.v[i] = (added.Z.v[i] & mask) | (result.Z.v[i] & ~mask);
            }
            tmp = p384_point_double(tmp);
        }
    }
    return result;
}


// -----------------------------------------------------------------------
// Scalar arithmetic mod n.
// -----------------------------------------------------------------------

[[nodiscard]]
static inline auto p384_scalar_from_bytes96( // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    const uint8_t b[96]) noexcept -> Fe384
{
    uint32_t w[24]; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    for (int i = 0; i < 24; ++i) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        const int j = 23 - i; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        const uint8_t* p = b + (j * 4); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        w[i] = (static_cast<uint32_t>(p[0]) << 24U) |
               (static_cast<uint32_t>(p[1]) << 16U) |
               (static_cast<uint32_t>(p[2]) <<  8U) |
                static_cast<uint32_t>(p[3]);
    }

    uint64_t acc[12]{}; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    for (int i = 0; i < 12; ++i) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        acc[i] = static_cast<uint64_t>(w[2 * i]) | (static_cast<uint64_t>(w[(2 * i) + 1]) << 32U);
    }

    using u128 = unsigned __int128;
    for (int step = 5; step >= 0; --step) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        const uint64_t hi = acc[step + 6]; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        if (hi == 0U) { continue; }
        acc[step + 6] = 0; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        int64_t borrow = 0;
        for (int i = 0; i < 6; ++i) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
            const auto prod = static_cast<u128>(hi) * p384_n[i];
            const int64_t diff = static_cast<int64_t>(acc[step + i])
                - static_cast<int64_t>(static_cast<uint64_t>(prod)) + borrow;
            acc[step + i] = static_cast<uint64_t>(diff);
            borrow = -(static_cast<int64_t>(static_cast<uint64_t>(prod >> 64U)) + (diff >> 63));
        }
        acc[step + 6] = static_cast<uint64_t>(static_cast<int64_t>(acc[step + 6]) + borrow); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    }

    Fe384 r{{acc[0], acc[1], acc[2], acc[3], acc[4], acc[5]}}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)

    // Final conditional subtract mod n.
    Fe384 sub{};
    auto t = static_cast<u128>(r.v[0]) - p384_n[0];
    sub.v[0] = static_cast<uint64_t>(t);
    auto borrow_f = static_cast<uint64_t>(t >> 127U);
    t = static_cast<u128>(r.v[1]) - p384_n[1] - borrow_f;
    sub.v[1] = static_cast<uint64_t>(t);
    borrow_f = static_cast<uint64_t>(t >> 127U);
    t = static_cast<u128>(r.v[2]) - p384_n[2] - borrow_f;
    sub.v[2] = static_cast<uint64_t>(t);
    borrow_f = static_cast<uint64_t>(t >> 127U);
    t = static_cast<u128>(r.v[3]) - p384_n[3] - borrow_f;
    sub.v[3] = static_cast<uint64_t>(t);
    borrow_f = static_cast<uint64_t>(t >> 127U);
    t = static_cast<u128>(r.v[4]) - p384_n[4] - borrow_f;
    sub.v[4] = static_cast<uint64_t>(t);
    borrow_f = static_cast<uint64_t>(t >> 127U);
    t = static_cast<u128>(r.v[5]) - p384_n[5] - borrow_f;
    sub.v[5] = static_cast<uint64_t>(t);
    borrow_f = static_cast<uint64_t>(t >> 127U);
    const uint64_t mask_f = 0U - (1U - borrow_f);
    return Fe384{{
        (sub.v[0] & mask_f) | (r.v[0] & ~mask_f),
        (sub.v[1] & mask_f) | (r.v[1] & ~mask_f),
        (sub.v[2] & mask_f) | (r.v[2] & ~mask_f),
        (sub.v[3] & mask_f) | (r.v[3] & ~mask_f),
        (sub.v[4] & mask_f) | (r.v[4] & ~mask_f),
        (sub.v[5] & mask_f) | (r.v[5] & ~mask_f),
    }};
}

[[nodiscard]]
static inline auto p384_scalar_from_bytes48( // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    const uint8_t b[48]) noexcept -> Fe384
{
    Fe384 r{};
    for (int i = 0; i < 6; ++i) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        const uint8_t* p = b + ((5 - i) * 8); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        r.v[i] =
            (static_cast<uint64_t>(p[0]) << 56U) | (static_cast<uint64_t>(p[1]) << 48U) |
            (static_cast<uint64_t>(p[2]) << 40U) | (static_cast<uint64_t>(p[3]) << 32U) |
            (static_cast<uint64_t>(p[4]) << 24U) | (static_cast<uint64_t>(p[5]) << 16U) |
            (static_cast<uint64_t>(p[6]) <<  8U) |  static_cast<uint64_t>(p[7]);
    }
    using u128 = unsigned __int128;
    Fe384 sub{};
    auto t = static_cast<u128>(r.v[0]) - p384_n[0];
    sub.v[0] = static_cast<uint64_t>(t);
    auto borrow = static_cast<uint64_t>(t >> 127U);
    t = static_cast<u128>(r.v[1]) - p384_n[1] - borrow;
    sub.v[1] = static_cast<uint64_t>(t);
    borrow = static_cast<uint64_t>(t >> 127U);
    t = static_cast<u128>(r.v[2]) - p384_n[2] - borrow;
    sub.v[2] = static_cast<uint64_t>(t);
    borrow = static_cast<uint64_t>(t >> 127U);
    t = static_cast<u128>(r.v[3]) - p384_n[3] - borrow;
    sub.v[3] = static_cast<uint64_t>(t);
    borrow = static_cast<uint64_t>(t >> 127U);
    t = static_cast<u128>(r.v[4]) - p384_n[4] - borrow;
    sub.v[4] = static_cast<uint64_t>(t);
    borrow = static_cast<uint64_t>(t >> 127U);
    t = static_cast<u128>(r.v[5]) - p384_n[5] - borrow;
    sub.v[5] = static_cast<uint64_t>(t);
    borrow = static_cast<uint64_t>(t >> 127U);
    const uint64_t mask = 0U - (1U - borrow);
    return Fe384{{
        (sub.v[0] & mask) | (r.v[0] & ~mask),
        (sub.v[1] & mask) | (r.v[1] & ~mask),
        (sub.v[2] & mask) | (r.v[2] & ~mask),
        (sub.v[3] & mask) | (r.v[3] & ~mask),
        (sub.v[4] & mask) | (r.v[4] & ~mask),
        (sub.v[5] & mask) | (r.v[5] & ~mask),
    }};
}

[[nodiscard]]
static inline auto p384_scalar_add( // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    const Fe384& a, const Fe384& b) noexcept -> Fe384
{
    using u128 = unsigned __int128;
    auto t = static_cast<u128>(a.v[0]) + b.v[0];
    Fe384 r{};
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
    const uint64_t overflow = static_cast<uint64_t>(t >> 64U);

    Fe384 sub{};
    auto s = static_cast<u128>(r.v[0]) - p384_n[0];
    sub.v[0] = static_cast<uint64_t>(s);
    auto borrow = static_cast<uint64_t>(s >> 127U);
    s = static_cast<u128>(r.v[1]) - p384_n[1] - borrow;
    sub.v[1] = static_cast<uint64_t>(s);
    borrow = static_cast<uint64_t>(s >> 127U);
    s = static_cast<u128>(r.v[2]) - p384_n[2] - borrow;
    sub.v[2] = static_cast<uint64_t>(s);
    borrow = static_cast<uint64_t>(s >> 127U);
    s = static_cast<u128>(r.v[3]) - p384_n[3] - borrow;
    sub.v[3] = static_cast<uint64_t>(s);
    borrow = static_cast<uint64_t>(s >> 127U);
    s = static_cast<u128>(r.v[4]) - p384_n[4] - borrow;
    sub.v[4] = static_cast<uint64_t>(s);
    borrow = static_cast<uint64_t>(s >> 127U);
    s = static_cast<u128>(r.v[5]) - p384_n[5] - borrow;
    sub.v[5] = static_cast<uint64_t>(s);
    borrow = static_cast<uint64_t>(s >> 127U);
    const uint64_t use_sub = overflow | (1U - borrow);
    const uint64_t mask = 0U - use_sub;
    return Fe384{{
        (sub.v[0] & mask) | (r.v[0] & ~mask),
        (sub.v[1] & mask) | (r.v[1] & ~mask),
        (sub.v[2] & mask) | (r.v[2] & ~mask),
        (sub.v[3] & mask) | (r.v[3] & ~mask),
        (sub.v[4] & mask) | (r.v[4] & ~mask),
        (sub.v[5] & mask) | (r.v[5] & ~mask),
    }};
}

[[nodiscard]]
// Montgomery multiplication CIOS for P-384 group order.
// Computes a*b*R^{-1} mod n where R = 2^384.
// n_prime = -n[0]^{-1} mod 2^64 = 0x6ed46089e88fdc45
[[nodiscard]]
static inline auto p384_mont_mul_n(const Fe384& a, const Fe384& b) noexcept -> Fe384
{
    using u128 = unsigned __int128;
    constexpr int s = 6; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    constexpr uint64_t n_prime = 0x6ed46089e88fdc45ULL;

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
        tt = static_cast<u128>(m) * p384_n[0] + t[0];
        carry = static_cast<uint64_t>(tt >> 64U);
        for (int j = 1; j < s; ++j) {
            tt       = static_cast<u128>(m) * p384_n[j] + t[j] + carry;
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

    Fe384 r{{t[0], t[1], t[2], t[3], t[4], t[5]}}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    const uint64_t overflow = t[s];

    Fe384 sub{};
    auto st = static_cast<u128>(r.v[0]) - p384_n[0];
    sub.v[0] = static_cast<uint64_t>(st);
    auto borrow = static_cast<uint64_t>(st >> 127U);
    st = static_cast<u128>(r.v[1]) - p384_n[1] - borrow;
    sub.v[1] = static_cast<uint64_t>(st);
    borrow = static_cast<uint64_t>(st >> 127U);
    st = static_cast<u128>(r.v[2]) - p384_n[2] - borrow;
    sub.v[2] = static_cast<uint64_t>(st);
    borrow = static_cast<uint64_t>(st >> 127U);
    st = static_cast<u128>(r.v[3]) - p384_n[3] - borrow;
    sub.v[3] = static_cast<uint64_t>(st);
    borrow = static_cast<uint64_t>(st >> 127U);
    st = static_cast<u128>(r.v[4]) - p384_n[4] - borrow;
    sub.v[4] = static_cast<uint64_t>(st);
    borrow = static_cast<uint64_t>(st >> 127U);
    st = static_cast<u128>(r.v[5]) - p384_n[5] - borrow;
    sub.v[5] = static_cast<uint64_t>(st);
    borrow = static_cast<uint64_t>(st >> 127U);
    const uint64_t use_sub = overflow | (1U - borrow);
    const uint64_t mask = 0U - use_sub;
    return Fe384{{
        (sub.v[0] & mask) | (r.v[0] & ~mask),
        (sub.v[1] & mask) | (r.v[1] & ~mask),
        (sub.v[2] & mask) | (r.v[2] & ~mask),
        (sub.v[3] & mask) | (r.v[3] & ~mask),
        (sub.v[4] & mask) | (r.v[4] & ~mask),
        (sub.v[5] & mask) | (r.v[5] & ~mask),
    }};
}

// Scalar mod-n multiply for P-384: a*b mod n.
// R^2 mod n = 0x0c84ee012b39bf213fb05b7a28266895d40d49174aab1cc5bc3e483afcb82947ff3d81e5df1aa4192d319b2419b409a9
[[nodiscard]]
static inline auto p384_scalar_mul_mod_n(
    const Fe384& a, const Fe384& b) noexcept -> Fe384
{
    static constexpr Fe384 r2_mod_n = {{
        0x2d319b2419b409a9ULL,
        0xff3d81e5df1aa419ULL,
        0xbc3e483afcb82947ULL,
        0xd40d49174aab1cc5ULL,
        0x3fb05b7a28266895ULL,
        0x0c84ee012b39bf21ULL,
    }};
    const Fe384 a_mont = p384_mont_mul_n(a, r2_mod_n);
    return p384_mont_mul_n(a_mont, b);
}

[[nodiscard]]
static inline auto p384_scalar_invert(const Fe384& a) noexcept -> Fe384 {
    // n-2 as 6 × 64-bit LE limbs
    static constexpr uint64_t nm2[6] = { // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
        0xecec196accc52971ULL,
        0x581a0db248b0a77aULL,
        0xc7634d81f4372ddfULL,
        0xffffffffffffffffULL,
        0xffffffffffffffffULL,
        0xffffffffffffffffULL,
    };
    Fe384 result{{1ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL}};
    for (int word = 5; word >= 0; --word) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        for (int bit = 63; bit >= 0; --bit) {
            result = p384_scalar_mul_mod_n(result, result);
            if (((nm2[word] >> static_cast<unsigned>(bit)) & 1U) != 0U) {
                result = p384_scalar_mul_mod_n(result, a);
            }
        }
    }
    return result;
}

[[nodiscard]]
static inline auto p384_scalar_is_zero(const Fe384& a) noexcept -> bool {
    return (a.v[0] | a.v[1] | a.v[2] | a.v[3] | a.v[4] | a.v[5]) == 0U;
}


// -----------------------------------------------------------------------
// Key pair generation and public key encoding.
// -----------------------------------------------------------------------

static inline void p384_compute_public_key( // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    const uint8_t private_scalar_be[48],
    uint8_t public_key_uncompressed[97]) noexcept // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
{
    const P384Point pub = p384_to_affine(p384_scalar_mul(
        P384Point{.X = p384_Gx, .Y = p384_Gy, .Z = fe384_one},
        private_scalar_be));
    public_key_uncompressed[0] = 0x04U;
    fe384_to_bytes(pub.X, public_key_uncompressed + 1);  // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    fe384_to_bytes(pub.Y, public_key_uncompressed + 49); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic,cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
}


}  // namespace arm_asm::detail
