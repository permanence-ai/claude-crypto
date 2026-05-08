// SPDX-License-Identifier: Apache-2.0

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
// Jacobian point and affine point.
// -----------------------------------------------------------------------

struct P384Point {
    Fe384 X;
    Fe384 Y;
    Fe384 Z;
};

struct P384AffinePoint {
    Fe384 X;
    Fe384 Y;
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

// Validate an uncompressed P-384 public key (x, y already loaded as field elements).
// Checks: x < p, y < p, (x,y) != (0,0), y² == x³ - 3x + b mod p.
[[nodiscard]]
static inline auto p384_validate_public_point(const Fe384& x, const Fe384& y) noexcept -> bool {
    Fe384 tmp{};
    if (fe384_sub_p(x, tmp) == 0U) { return false; }
    if (fe384_sub_p(y, tmp) == 0U) { return false; }
    if (fe384_is_zero(x) && fe384_is_zero(y)) { return false; }
    const Fe384 y2   = fe384_sqr(y);
    const Fe384 x3   = fe384_mul(fe384_sqr(x), x);
    const Fe384 x3_b = fe384_add(x3, p384_b);
    const Fe384 x2   = fe384_add(x, x);
    const Fe384 x3x  = fe384_add(x2, x);
    const Fe384 rhs  = fe384_sub(x3_b, x3x);
    return fe384_equal(y2, rhs);
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

    const Fe384 gsq    = fe384_sqr(gamma);
    const Fe384 gsq2   = fe384_add(gsq, gsq);
    const Fe384 gsq4   = fe384_add(gsq2, gsq2);
    const Fe384 gamma8 = fe384_add(gsq4, gsq4);
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
// Mixed Jacobian–affine add: p (Jacobian) + q (affine, Z=1).
// -----------------------------------------------------------------------

[[nodiscard]]
static inline auto p384_point_add_affine(const P384Point& p, const P384AffinePoint& q) noexcept -> P384Point
{
    if (p384_point_is_identity(p)) {
        return P384Point{.X = q.X, .Y = q.Y, .Z = fe384_one};
    }

    const Fe384 z1sq = fe384_sqr(p.Z);
    const Fe384 u2   = fe384_mul(q.X, z1sq);
    const Fe384 s2   = fe384_mul(q.Y, fe384_mul(p.Z, z1sq));
    const Fe384 h    = fe384_sub(u2, p.X);
    const Fe384 r    = fe384_sub(s2, p.Y);

    if (fe384_is_zero(h) && fe384_is_zero(r)) {
        return p384_point_double(p);
    }

    const Fe384 h2   = fe384_sqr(h);
    const Fe384 h3   = fe384_mul(h, h2);
    const Fe384 u1h2 = fe384_mul(p.X, h2);
    const Fe384 x3   = fe384_sub(fe384_sub(fe384_sqr(r), h3), fe384_add(u1h2, u1h2));
    const Fe384 y3   = fe384_sub(fe384_mul(r, fe384_sub(u1h2, x3)), fe384_mul(p.Y, h3));
    const Fe384 z3   = fe384_mul(h, p.Z);

    return P384Point{
        .X = x3,
        .Y = y3,
        .Z = z3,
    };
}


// -----------------------------------------------------------------------
// Precomputed [1..15]*G table for 4-bit fixed-base window.
// -----------------------------------------------------------------------

static constexpr P384AffinePoint p384_G_table[15] = { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    // [1]*G
    {{0x3a545e3872760ab7ULL, 0x5502f25dbf55296cULL, 0x59f741e082542a38ULL, 0x6e1d3b628ba79b98ULL, 0x8eb1c71ef320ad74ULL, 0xaa87ca22be8b0537ULL}, {0x7a431d7c90ea0e5fULL, 0x0a60b1ce1d7e819dULL, 0xe9da3113b5f0b8c0ULL, 0xf8f41dbd289a147cULL, 0x5d9e98bf9292dc29ULL, 0x3617de4a96262c6fULL}},
    // [2]*G
    {{0x5b96a9c75295df61ULL, 0x4fe0e86ebe0e64f8ULL, 0x51d207d19fb96e9eULL, 0x89025959a6f434d6ULL, 0x69260045c55b97f0ULL, 0x08d999057ba3d2d9ULL}, {0x61501e700a940e80ULL, 0x5ffd43e94d39e22dULL, 0x904e505f256ab425ULL, 0xb275d875bc6cc43eULL, 0xb7bfe8dffd6dba74ULL, 0x8e80f1fa5b1b3cedULL}},
    // [3]*G
    {{0x02d7e5c70500c831ULL, 0xb408bbae5026580dULL, 0xbea4f240d3566da6ULL, 0xcb9d3910202dcd06ULL, 0x64793c7e5fdc7d98ULL, 0x077a41d4606ffa14ULL}, {0xb65f28600a2f1df1ULL, 0xc24abd6be4b5d298ULL, 0xf7684c0edc111eacULL, 0x8520b41c85115aa5ULL, 0x7d0bbe9602a9fc99ULL, 0xc995f7ca0b0c4283ULL}},
    // [4]*G
    {{0xe1efd631c63e1835ULL, 0x1589a1597e3a5120ULL, 0xa55dc8ad51dcfc9dULL, 0x97e709bd0b4ca0acULL, 0xc1c8aad977321debULL, 0x138251cd52ac9298ULL}, {0x549f1c02b270ed67ULL, 0xed7387be37bba569ULL, 0xab0e63cf792aa4dcULL, 0x6dc45d918abc09f3ULL, 0x31e8a28181ab5661ULL, 0xcacae29869a62e16ULL}},
    // [5]*G
    {{0x0abcdbc3836d84bcULL, 0x37882f4a1ca297e6ULL, 0x4f6661cbe56583b0ULL, 0xf208e51dbff98fc5ULL, 0x573cac5ea025e467ULL, 0x11de24a2c251c777ULL}, {0x184414abe6c1713aULL, 0x3177686d0ae8fb33ULL, 0x8c986533b6901aebULL, 0x284b447754d5dee8ULL, 0x0f5837e90a00e7c5ULL, 0x8fa696c77440f92dULL}},
    // [6]*G
    {{0x0937f0854e35c5dfULL, 0x21317d7202ff30e5ULL, 0x1cbd41f262573830ULL, 0xc33ebcbb7f0f5da5ULL, 0x226fe0d26f2d15d3ULL, 0x627be1acd064d2b2ULL}, {0x1733a408d3f0f934ULL, 0x04c45b8d84e16531ULL, 0x99864f6137154416ULL, 0xb2c95352644f774cULL, 0x1be6dda6c14f1575ULL, 0x09766a4cb3f8b1c2ULL}},
    // [7]*G
    {{0x040f05b48fb6d0e1ULL, 0x8b05526f55b9ebb2ULL, 0x2d58cc9dfa7b1c50ULL, 0xad6fe997fbea5ffaULL, 0xf29f8ebf234edffeULL, 0x283c1d7365ce4788ULL}, {0x64664cdac512ef8cULL, 0x30d84ede32a78f9eULL, 0xd9c92cd01dbd2256ULL, 0x1a61d867ed799729ULL, 0xba52efdb8c169047ULL, 0x9475c99061e41b88ULL}},
    // [8]*G
    {{0xe6e9b269d822c87dULL, 0x5a3258d6f403d5ecULL, 0x900c3c73256f11fbULL, 0x45bf227fbe58190aULL, 0x75114297a6fa3834ULL, 0x1692778ea596e0beULL}, {0x6f6abfa4022b0ad2ULL, 0x6bade1e9cdd1708dULL, 0xbd1c30c2ec0eec19ULL, 0x22554adc6d521cd4ULL, 0x835388ba3db8fd0eULL, 0xdcd2365700d4106aULL}},
    // [9]*G
    {{0x5c55e4461079118bULL, 0xc388528bfee2b953ULL, 0xc6cb1ee285fb6e21ULL, 0x2216f7291e6fd3baULL, 0xf1bf29b8b025b78fULL, 0x8f0a39a4049bcb3eULL}, {0x262da4f9ac664af8ULL, 0x9e743efedfd51b68ULL, 0xb7678854aed9b302ULL, 0x9a9b3d7ca3c400c6ULL, 0x452c4a5322c3a979ULL, 0x62c77e1438b601d6ULL}},
    // [10]*G
    {{0xa9cb2d13186658fbULL, 0xed8e85ab507bf91aULL, 0x931d5c29291238ccULL, 0x4f372d90b79b9e88ULL, 0x678d29d6ef4fde86ULL, 0xa669c5563bd67eecULL}, {0x97784f6ab73a21ddULL, 0x296d8195248288d9ULL, 0xc502df78c3b705a8ULL, 0xf70119550c183c31ULL, 0x22d9083db5f0ecddULL, 0xa988b72ae7c1279fULL}},
    // [11]*G
    {{0x26356f3b55b4ddd8ULL, 0x4749b66e3afb81d6ULL, 0x56c9fd14892d3f8cULL, 0x7fe935ed5837c374ULL, 0xda1eeec2904816c5ULL, 0x099056e27da7b998ULL}, {0x7d5dba8138c5e0bbULL, 0x5466d51263aaff35ULL, 0x43ff93f41b52a325ULL, 0x6fc4eed8dfc363fdULL, 0x688505544ac5e039ULL, 0x2e4c0c234e30ab96ULL}},
    // [12]*G
    {{0x66da2ea77d2a7022ULL, 0xda4a5e22da817cb4ULL, 0x648af2691a481406ULL, 0x8c2ed5e41f6d0e21ULL, 0xab3ac421dcf683d0ULL, 0x952a7a349bd49289ULL}, {0x9ef6bacce21bd16eULL, 0x031aa64589743e22ULL, 0xb9028b096196b50dULL, 0x09fb8036ce18a0ebULL, 0x63052deae6f66f2eULL, 0xa0320faf84b5bc05ULL}},
    // [13]*G
    {{0xaaf1ca1e3b5cbce7ULL, 0x9ee5f441abd99f1bULL, 0x6267bcd1f0f11c13ULL, 0x9632bff9f01f873fULL, 0xafdaf5002ffcc6abULL, 0xa567ba97b67aea5bULL}, {0x6423a12736f429ccULL, 0x776bcb8272218a7dULL, 0x86329be057857d66ULL, 0x5185595046932ec0ULL, 0x644e4147af164eccULL, 0xde1b38b3989f3318ULL}},
    // [14]*G
    {{0x37209accf0f59ea0ULL, 0x41aba24dbc02de66ULL, 0x5de541eb651cca2cULL, 0x877b1dffd23e7dc9ULL, 0x6bbeac481b89d2b0ULL, 0xe8c8f94d44fbc239ULL}, {0xd7ee5c9e1b67b888ULL, 0xfc468ba05509de22ULL, 0xc8319413a09d0f48ULL, 0x33b86191e7728d79ULL, 0x932bcbf6de52c8a9ULL, 0x891ae44356fc8ae0ULL}},
    // [15]*G
    {{0x4b88701a9606860bULL, 0xa849557a10b6383bULL, 0x5b21f9f7da7c4e9cULL, 0x22a94156fff01c20ULL, 0x8cc15c11d8135255ULL, 0xb3d13fc8b32b0105ULL}, {0x985d588d33f7bd62ULL, 0x838d24f8b284af50ULL, 0x84d1114373dfbfd9ULL, 0xeebac4a11d749af4ULL, 0x1b049b2536164b1bULL, 0x152919e7df9162a6ULL}},
}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)


// -----------------------------------------------------------------------
// Constant-time helpers for fixed-base scalar multiplication.
// -----------------------------------------------------------------------

[[nodiscard]]
static inline auto p384_point_ct_select(
    const P384Point& a, const P384Point& b, uint64_t use_a) noexcept -> P384Point
{
    const uint64_t mask = 0U - use_a;
    P384Point r{};
    for (int i = 0; i < 6; ++i) {
        r.X.v[i] = (a.X.v[i] & mask) | (b.X.v[i] & ~mask);
        r.Y.v[i] = (a.Y.v[i] & mask) | (b.Y.v[i] & ~mask);
        r.Z.v[i] = (a.Z.v[i] & mask) | (b.Z.v[i] & ~mask);
    }
    return r;
}

[[nodiscard]]
static inline auto p384_G_table_select(unsigned nibble) noexcept -> P384AffinePoint
{
    P384AffinePoint r = p384_G_table[0]; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    for (unsigned i = 1; i < 15U; ++i) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        const uint64_t mask = 0U - static_cast<uint64_t>(i + 1U == nibble);
        for (int j = 0; j < 6; ++j) {
            r.X.v[j] = (p384_G_table[i].X.v[j] & mask) | (r.X.v[j] & ~mask); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
            r.Y.v[j] = (p384_G_table[i].Y.v[j] & mask) | (r.Y.v[j] & ~mask); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
        }
    }
    return r;
}


// CT point doubling: branch-free with respect to identity.
[[nodiscard]]
static inline auto p384_point_double_ct(const P384Point& p) noexcept -> P384Point
{
    const P384Point doubled = [&]() noexcept -> P384Point {
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
        const Fe384 z3    = fe384_sub(fe384_sub(fe384_sqr(fe384_add(p.Y, p.Z)), gamma), delta);
        const Fe384 gsq   = fe384_sqr(gamma);
        const Fe384 gsq2  = fe384_add(gsq, gsq);
        const Fe384 gsq4  = fe384_add(gsq2, gsq2);
        const Fe384 gamma8 = fe384_add(gsq4, gsq4);
        const Fe384 y3    = fe384_sub(fe384_mul(alpha, fe384_sub(beta4, x3)), gamma8);
        return P384Point{.X = x3, .Y = y3, .Z = z3};
    }();
    const uint64_t is_identity = static_cast<uint64_t>(fe384_is_zero(p.Z));
    return p384_point_ct_select(p384_identity, doubled, is_identity);
}

// CT mixed Jacobian+affine add: branch-free with respect to identity.
[[nodiscard]]
static inline auto p384_point_add_affine_ct(const P384Point& p, const P384AffinePoint& q) noexcept -> P384Point
{
    const P384Point added = [&]() noexcept -> P384Point {
        const Fe384 z1sq = fe384_sqr(p.Z);
        const Fe384 u2   = fe384_mul(q.X, z1sq);
        const Fe384 s2   = fe384_mul(q.Y, fe384_mul(p.Z, z1sq));
        const Fe384 h    = fe384_sub(u2, p.X);
        const Fe384 r    = fe384_sub(s2, p.Y);
        const Fe384 h2   = fe384_sqr(h);
        const Fe384 h3   = fe384_mul(h, h2);
        const Fe384 u1h2 = fe384_mul(p.X, h2);
        const Fe384 x3   = fe384_sub(fe384_sub(fe384_sqr(r), h3), fe384_add(u1h2, u1h2));
        const Fe384 y3   = fe384_sub(fe384_mul(r, fe384_sub(u1h2, x3)), fe384_mul(p.Y, h3));
        const Fe384 z3   = fe384_mul(h, p.Z);
        return P384Point{.X = x3, .Y = y3, .Z = z3};
    }();
    const P384Point q_jac{.X = q.X, .Y = q.Y, .Z = fe384_one};
    const uint64_t is_identity = static_cast<uint64_t>(fe384_is_zero(p.Z));
    return p384_point_ct_select(q_jac, added, is_identity);
}


// -----------------------------------------------------------------------
// Fixed-base scalar multiplication using 4-bit window: k·G.
// scalar is 48-byte big-endian.
// Fully constant-time: no branches on secret data, including identity state.
// -----------------------------------------------------------------------

[[nodiscard]]
static inline auto p384_scalar_mul_base( // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    const uint8_t scalar[48]) noexcept -> P384Point // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
{
    P384Point result = p384_identity;

    for (int byte_i = 0; byte_i < 48; ++byte_i) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        const uint8_t byte_val = scalar[byte_i]; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)

        for (int pass = 0; pass < 2; ++pass) {
            result = p384_point_double_ct(result);
            result = p384_point_double_ct(result);
            result = p384_point_double_ct(result);
            result = p384_point_double_ct(result);

            const auto nibble = static_cast<unsigned>(
                (pass == 0) ? (byte_val >> 4U) : (byte_val & 0x0fU));

            const P384AffinePoint tab = p384_G_table_select(nibble);
            const P384Point added = p384_point_add_affine_ct(result, tab);
            result = p384_point_ct_select(added, result, static_cast<uint64_t>(nibble != 0U));
        }
    }
    return result;
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
        acc[i] = static_cast<uint64_t>(w[2U * static_cast<std::size_t>(i)]) | (static_cast<uint64_t>(w[2U * static_cast<std::size_t>(i) + 1]) << 32U);
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
            borrow = -(static_cast<int64_t>(static_cast<uint64_t>(prod >> 64U)) + (diff >> 63)); // NOLINT(hicpp-signed-bitwise)
        }
        acc[step + 6] = static_cast<uint64_t>(static_cast<int64_t>(acc[step + 6]) + borrow); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    }

    const Fe384 r{{acc[0], acc[1], acc[2], acc[3], acc[4], acc[5]}}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)

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
        const uint8_t* p = b + static_cast<std::ptrdiff_t>(5 - i) * 8; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
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

    const Fe384 r{{t[0], t[1], t[2], t[3], t[4], t[5]}}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
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

// Scalar inversion mod n using an addition chain that stays in Montgomery domain.
//
// n-2 bit pattern (MSB first):
//   bits 383..192: 192 ones (all-1 words 3..5)
//   bits 191..0:   irregular (C7634D81F4372DDF 581A0DB248B0A77A ECEC196ACCC52971)
//
// Notation: [v] = v*R mod n  (Montgomery representation).
// mont_mul([x], [y]) = [x*y].
// Cost: ~490 mont_muls (vs ~1344 for generic square-and-multiply with double conversion).
[[nodiscard]]
static inline auto p384_scalar_invert(const Fe384& a) noexcept -> Fe384 {
    static constexpr Fe384 r2_mod_n = {{
        0x2d319b2419b409a9ULL,
        0xff3d81e5df1aa419ULL,
        0xbc3e483afcb82947ULL,
        0xd40d49174aab1cc5ULL,
        0x3fb05b7a28266895ULL,
        0x0c84ee012b39bf21ULL,
    }};
    static constexpr Fe384 one = {{1ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL}};

    // Convert a to Montgomery domain: [a] = a*R mod n.
    const Fe384 aM = p384_mont_mul_n(a, r2_mod_n);

    // Build [a^(2^k-1)] for k = 1,2,4,8,16,32,64 via doubling-chain:
    //   p_k = [a^(2^k - 1)]:
    //     (1) square p_{k/2} by (k/2) to get [a^(2^{k/2}*(2^{k/2}-1))]
    //     (2) mont_mul result with p_{k/2} = [a^(2^{k/2}-1)]
    //         product = [a^(2^{k/2}*(2^{k/2}-1) + (2^{k/2}-1))] = [a^((2^{k/2}-1)*(2^{k/2}+1))] = [a^(2^k-1)]
    auto sqn = [](Fe384 x, int n) -> Fe384 { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        for (int i = 0; i < n; ++i) { x = p384_mont_mul_n(x, x); }
        return x;
    };
    const Fe384 p1  = aM;                                          // [a^(2^1-1)]
    const Fe384 p2  = p384_mont_mul_n(sqn(p1,  1), p1);           // [a^(2^2-1)]  NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    const Fe384 p4  = p384_mont_mul_n(sqn(p2,  2), p2);           // [a^(2^4-1)]  NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    const Fe384 p8  = p384_mont_mul_n(sqn(p4,  4), p4);           // [a^(2^8-1)]  NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    const Fe384 p16 = p384_mont_mul_n(sqn(p8,  8), p8);           // [a^(2^16-1)] NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    const Fe384 p32 = p384_mont_mul_n(sqn(p16, 16), p16);         // [a^(2^32-1)] NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    const Fe384 p64 = p384_mont_mul_n(sqn(p32, 32), p32);         // [a^(2^64-1)] NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)

    // Accumulate top 192 ones (bits 383..192) using precomputed windows.
    // [a^(2^128-1)]: square p64 by 64, multiply by p64.
    const Fe384 p128 = p384_mont_mul_n(sqn(p64, 64), p64);        // [a^(2^128-1)] NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    // [a^(2^192-1)]: square p128 by 64, multiply by p64.
    Fe384 result = p384_mont_mul_n(sqn(p128, 64), p64);           // [a^(2^192-1)] NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)

    // Process lower 192 bits of n-2: 0xC7634D81F4372DDF_581A0DB248B0A77A_ECEC196ACCC52971.
    static constexpr uint64_t nm2_lo[3] = { // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
        0xecec196accc52971ULL,  // word[0]  (LSB)
        0x581a0db248b0a77aULL,  // word[1]
        0xc7634d81f4372ddfULL,  // word[2]  (MSB of lower 192 bits)
    };
    for (int word = 2; word >= 0; --word) {
        for (int bit = 63; bit >= 0; --bit) {
            result = p384_mont_mul_n(result, result);
            if (((nm2_lo[word] >> static_cast<unsigned>(bit)) & 1U) != 0U) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
                result = p384_mont_mul_n(result, aM);
            }
        }
    }

    // Convert back from Montgomery domain: [a^(n-2)] → a^(n-2) mod n.
    return p384_mont_mul_n(result, one);
}

[[nodiscard]]
static inline auto p384_scalar_is_zero(const Fe384& a) noexcept -> bool {
    return (a.v[0] | a.v[1] | a.v[2] | a.v[3] | a.v[4] | a.v[5]) == 0U;
}

// Strictly decode a 48-byte big-endian ECDSA signature scalar (r or s).
// Returns true and writes the scalar iff 1 <= val < n; rejects val == 0 or val >= n.
[[nodiscard]]
static inline auto p384_scalar_sig_decode( // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    const uint8_t b[48], Fe384& out) noexcept -> bool // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
{
    Fe384 r{};
    for (int i = 0; i < 6; ++i) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        const uint8_t* p = b + static_cast<std::ptrdiff_t>(5 - i) * 8; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        r.v[i] =
            (static_cast<uint64_t>(p[0]) << 56U) | (static_cast<uint64_t>(p[1]) << 48U) |
            (static_cast<uint64_t>(p[2]) << 40U) | (static_cast<uint64_t>(p[3]) << 32U) |
            (static_cast<uint64_t>(p[4]) << 24U) | (static_cast<uint64_t>(p[5]) << 16U) |
            (static_cast<uint64_t>(p[6]) <<  8U) |  static_cast<uint64_t>(p[7]);
    }
    if (p384_scalar_is_zero(r)) { return false; }
    using u128 = unsigned __int128;
    auto t = static_cast<u128>(r.v[0]) - p384_n[0];
    auto borrow = static_cast<uint64_t>(t >> 127U);
    t = static_cast<u128>(r.v[1]) - p384_n[1] - borrow;
    borrow = static_cast<uint64_t>(t >> 127U);
    t = static_cast<u128>(r.v[2]) - p384_n[2] - borrow;
    borrow = static_cast<uint64_t>(t >> 127U);
    t = static_cast<u128>(r.v[3]) - p384_n[3] - borrow;
    borrow = static_cast<uint64_t>(t >> 127U);
    t = static_cast<u128>(r.v[4]) - p384_n[4] - borrow;
    borrow = static_cast<uint64_t>(t >> 127U);
    t = static_cast<u128>(r.v[5]) - p384_n[5] - borrow;
    borrow = static_cast<uint64_t>(t >> 127U);
    if (borrow == 0U) { return false; } // r >= n
    out = r;
    return true;
}


// -----------------------------------------------------------------------
// Key pair generation and public key encoding.
// -----------------------------------------------------------------------

static inline void p384_compute_public_key( // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    const uint8_t private_scalar_be[48],
    uint8_t public_key_uncompressed[97]) noexcept // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
{
    const P384Point pub = p384_to_affine(p384_scalar_mul_base(private_scalar_be));
    public_key_uncompressed[0] = 0x04U;
    fe384_to_bytes(pub.X, public_key_uncompressed + 1);  // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    fe384_to_bytes(pub.Y, public_key_uncompressed + 49); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic,cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
}


}  // namespace arm_asm::detail
