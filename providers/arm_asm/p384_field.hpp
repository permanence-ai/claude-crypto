// SPDX-License-Identifier: Apache-2.0

#pragma once

// P-384 (secp384r1) prime field arithmetic.
//
// Field prime: p = 2^384 − 2^128 − 2^96 + 2^32 − 1
// Represented as 6 × uint64_t little-endian 64-bit limbs, always in [0, p-1].
//
// Multiplication uses the Solinas fast reduction from FIPS 186-4 App. D.1.2.4.
// Per-word accumulation (word w covers bits [32w, 32w+31]):
//
//   r[0]  = c[0]  + c[12] + c[21] + c[20] − c[23]
//   r[1]  = c[1]  + c[13] + c[22] + c[23] − c[12] − c[20]
//   r[2]  = c[2]  + c[14] + c[23] − c[13] − c[21]
//   r[3]  = c[3]  + c[15] + c[12] + c[20] + c[21] − c[14] − c[22] − c[23]
//   r[4]  = c[4]  + c[21] + c[16] + c[13] + c[22] − c[15] − c[23]
//   r[5]  = c[5]  + c[22] + c[17] + c[14] + c[23] − c[16]
//   r[6]  = c[6]  + c[23] + c[18] + c[15] − c[17]
//   r[7]  = c[7]  + c[19] + c[16] − c[18]
//   r[8]  = c[8]  + c[20] + c[17] − c[19]
//   r[9]  = c[9]  + c[21] + c[18] − c[20]
//   r[10] = c[10] + c[22] + c[19] − c[21]
//   r[11] = c[11] + c[23] + c[20] − c[22]
//
// All arithmetic is constant-time with respect to field element inputs.

#include <cstddef>
#include <cstdint>
#include <cstring>


namespace arm_asm::detail {


struct Fe384 {
    uint64_t v[6]; // NOLINT(misc-non-private-member-variables-in-classes)
};

static constexpr Fe384 fe384_zero = {{0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL}};
static constexpr Fe384 fe384_one  = {{1ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL}};

// p in 6 × 64-bit LE limbs.
static constexpr Fe384 fe384_p = {{
    0x00000000ffffffffULL,
    0xffffffff00000000ULL,
    0xfffffffffffffffeULL,
    0xffffffffffffffffULL,
    0xffffffffffffffffULL,
    0xffffffffffffffffULL,
}};

// -----------------------------------------------------------------------
// Byte encoding (big-endian, matching SEC 1 / PSA wire format).
// -----------------------------------------------------------------------

[[nodiscard]]
static inline auto fe384_from_bytes( // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    const uint8_t b[48]) noexcept -> Fe384
{
    Fe384 r{};
    for (int i = 0; i < 6; ++i) {
        const uint8_t* p = b + (5 - i) * 8; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        r.v[i] =
            (static_cast<uint64_t>(p[0]) << 56U) | (static_cast<uint64_t>(p[1]) << 48U) |
            (static_cast<uint64_t>(p[2]) << 40U) | (static_cast<uint64_t>(p[3]) << 32U) |
            (static_cast<uint64_t>(p[4]) << 24U) | (static_cast<uint64_t>(p[5]) << 16U) |
            (static_cast<uint64_t>(p[6]) <<  8U) |  static_cast<uint64_t>(p[7]);
    }
    return r;
}

static inline void fe384_to_bytes( // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    const Fe384& a, uint8_t b[48]) noexcept
{
    for (int i = 0; i < 6; ++i) {
        uint8_t* p = b + (5 - i) * 8; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        p[0] = static_cast<uint8_t>(a.v[i] >> 56U);
        p[1] = static_cast<uint8_t>(a.v[i] >> 48U);
        p[2] = static_cast<uint8_t>(a.v[i] >> 40U);
        p[3] = static_cast<uint8_t>(a.v[i] >> 32U);
        p[4] = static_cast<uint8_t>(a.v[i] >> 24U);
        p[5] = static_cast<uint8_t>(a.v[i] >> 16U);
        p[6] = static_cast<uint8_t>(a.v[i] >>  8U);
        p[7] = static_cast<uint8_t>(a.v[i]);
    }
}

// -----------------------------------------------------------------------
// Internal helpers.
// -----------------------------------------------------------------------

[[nodiscard]]
static inline auto fe384_sub_p(const Fe384& a, Fe384& out) noexcept -> uint64_t {
    using u128 = unsigned __int128;
    constexpr uint64_t p0 = 0x00000000ffffffffULL;
    constexpr uint64_t p1 = 0xffffffff00000000ULL;
    constexpr uint64_t p2 = 0xfffffffffffffffeULL;
    constexpr uint64_t p3 = 0xffffffffffffffffULL;
    constexpr uint64_t p4 = 0xffffffffffffffffULL;
    constexpr uint64_t p5 = 0xffffffffffffffffULL;
    auto t = static_cast<u128>(a.v[0]) - p0;
    out.v[0] = static_cast<uint64_t>(t);
    auto borrow = static_cast<uint64_t>(t >> 127U);
    t = static_cast<u128>(a.v[1]) - p1 - borrow;
    out.v[1] = static_cast<uint64_t>(t);
    borrow = static_cast<uint64_t>(t >> 127U);
    t = static_cast<u128>(a.v[2]) - p2 - borrow;
    out.v[2] = static_cast<uint64_t>(t);
    borrow = static_cast<uint64_t>(t >> 127U);
    t = static_cast<u128>(a.v[3]) - p3 - borrow;
    out.v[3] = static_cast<uint64_t>(t);
    borrow = static_cast<uint64_t>(t >> 127U);
    t = static_cast<u128>(a.v[4]) - p4 - borrow;
    out.v[4] = static_cast<uint64_t>(t);
    borrow = static_cast<uint64_t>(t >> 127U);
    t = static_cast<u128>(a.v[5]) - p5 - borrow;
    out.v[5] = static_cast<uint64_t>(t);
    return static_cast<uint64_t>(t >> 127U);
}

[[nodiscard]]
static inline auto fe384_reduce_once(const Fe384& a, uint64_t overflow) noexcept -> Fe384 {
    Fe384 sub{};
    const uint64_t borrow = fe384_sub_p(a, sub);
    const uint64_t use_sub = overflow | (1U - borrow);
    const uint64_t mask = 0U - use_sub;
    return Fe384{{
        (sub.v[0] & mask) | (a.v[0] & ~mask),
        (sub.v[1] & mask) | (a.v[1] & ~mask),
        (sub.v[2] & mask) | (a.v[2] & ~mask),
        (sub.v[3] & mask) | (a.v[3] & ~mask),
        (sub.v[4] & mask) | (a.v[4] & ~mask),
        (sub.v[5] & mask) | (a.v[5] & ~mask),
    }};
}

// -----------------------------------------------------------------------
// Field addition and subtraction.
// -----------------------------------------------------------------------

[[nodiscard]]
static inline auto fe384_add(const Fe384& a, const Fe384& b) noexcept -> Fe384 {
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
    return fe384_reduce_once(r, static_cast<uint64_t>(t >> 64U));
}

[[nodiscard]]
static inline auto fe384_sub(const Fe384& a, const Fe384& b) noexcept -> Fe384 {
    using u128 = unsigned __int128;
    constexpr uint64_t p0 = 0x00000000ffffffffULL;
    constexpr uint64_t p1 = 0xffffffff00000000ULL;
    constexpr uint64_t p2 = 0xfffffffffffffffeULL;
    constexpr uint64_t p3 = 0xffffffffffffffffULL;
    constexpr uint64_t p4 = 0xffffffffffffffffULL;
    constexpr uint64_t p5 = 0xffffffffffffffffULL;
    auto t = static_cast<u128>(a.v[0]) - b.v[0];
    Fe384 r{};
    r.v[0] = static_cast<uint64_t>(t);
    auto borrow = static_cast<uint64_t>(t >> 127U);
    t = static_cast<u128>(a.v[1]) - b.v[1] - borrow;
    r.v[1] = static_cast<uint64_t>(t);
    borrow = static_cast<uint64_t>(t >> 127U);
    t = static_cast<u128>(a.v[2]) - b.v[2] - borrow;
    r.v[2] = static_cast<uint64_t>(t);
    borrow = static_cast<uint64_t>(t >> 127U);
    t = static_cast<u128>(a.v[3]) - b.v[3] - borrow;
    r.v[3] = static_cast<uint64_t>(t);
    borrow = static_cast<uint64_t>(t >> 127U);
    t = static_cast<u128>(a.v[4]) - b.v[4] - borrow;
    r.v[4] = static_cast<uint64_t>(t);
    borrow = static_cast<uint64_t>(t >> 127U);
    t = static_cast<u128>(a.v[5]) - b.v[5] - borrow;
    r.v[5] = static_cast<uint64_t>(t);
    borrow = static_cast<uint64_t>(t >> 127U);
    const uint64_t mask = 0U - borrow;
    t = static_cast<u128>(r.v[0]) + (p0 & mask);
    r.v[0] = static_cast<uint64_t>(t);
    auto carry = static_cast<uint64_t>(t >> 64U);
    t = static_cast<u128>(r.v[1]) + (p1 & mask) + carry;
    r.v[1] = static_cast<uint64_t>(t);
    carry = static_cast<uint64_t>(t >> 64U);
    t = static_cast<u128>(r.v[2]) + (p2 & mask) + carry;
    r.v[2] = static_cast<uint64_t>(t);
    carry = static_cast<uint64_t>(t >> 64U);
    t = static_cast<u128>(r.v[3]) + (p3 & mask) + carry;
    r.v[3] = static_cast<uint64_t>(t);
    carry = static_cast<uint64_t>(t >> 64U);
    t = static_cast<u128>(r.v[4]) + (p4 & mask) + carry;
    r.v[4] = static_cast<uint64_t>(t);
    carry = static_cast<uint64_t>(t >> 64U);
    t = static_cast<u128>(r.v[5]) + (p5 & mask) + carry;
    r.v[5] = static_cast<uint64_t>(t);
    return r;
}

[[nodiscard]]
static inline auto fe384_neg(const Fe384& a) noexcept -> Fe384 {
    using u128 = unsigned __int128;
    constexpr uint64_t p0 = 0x00000000ffffffffULL;
    constexpr uint64_t p1 = 0xffffffff00000000ULL;
    constexpr uint64_t p2 = 0xfffffffffffffffeULL;
    constexpr uint64_t p3 = 0xffffffffffffffffULL;
    constexpr uint64_t p4 = 0xffffffffffffffffULL;
    constexpr uint64_t p5 = 0xffffffffffffffffULL;
    auto t = static_cast<u128>(p0) - a.v[0];
    Fe384 r{};
    r.v[0] = static_cast<uint64_t>(t);
    auto borrow = static_cast<uint64_t>(t >> 127U);
    t = static_cast<u128>(p1) - a.v[1] - borrow;
    r.v[1] = static_cast<uint64_t>(t);
    borrow = static_cast<uint64_t>(t >> 127U);
    t = static_cast<u128>(p2) - a.v[2] - borrow;
    r.v[2] = static_cast<uint64_t>(t);
    borrow = static_cast<uint64_t>(t >> 127U);
    t = static_cast<u128>(p3) - a.v[3] - borrow;
    r.v[3] = static_cast<uint64_t>(t);
    borrow = static_cast<uint64_t>(t >> 127U);
    t = static_cast<u128>(p4) - a.v[4] - borrow;
    r.v[4] = static_cast<uint64_t>(t);
    borrow = static_cast<uint64_t>(t >> 127U);
    t = static_cast<u128>(p5) - a.v[5] - borrow;
    r.v[5] = static_cast<uint64_t>(t);
    return fe384_reduce_once(r, 0U);
}

// -----------------------------------------------------------------------
// Field multiplication via Solinas fast reduction.
// -----------------------------------------------------------------------

// Apply Solinas reduction mod p384.
// Input: 24 × 32-bit words c[0..23] representing a 768-bit value (c[0] = LSW).
// Output: 384-bit result in [0, p-1].
//
// Per-word accumulation derived from W^k mod p384 (W = 2^32) unsigned word decomposition.
// Each r[j] = c[j] + sum_{k=12}^{23} c[k] * (W^k mod p384)[j].
// Accumulated into unsigned __int128 (max ~2^67 per word) then carry-propagated.
// Overflow word: 2^384 mod p = W^0 - W^1 - W^2 + W^4 (signed, via carry-split).
[[nodiscard]]
static inline auto fe384_solinas( // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    const uint32_t c[24]) noexcept -> Fe384
{
    using u128 = unsigned __int128;

    // Precast to u128 to avoid 32×32 multiplication staying in 32-bit.
    const u128 c12 = c[12], c13 = c[13], c14 = c[14], c15 = c[15]; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    const u128 c16 = c[16], c17 = c[17], c18 = c[18], c19 = c[19]; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    const u128 c20 = c[20], c21 = c[21], c22 = c[22], c23 = c[23]; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)

    // Unsigned per-word accumulation (W^k mod p384 words derived from field polynomial).
    // W^22[0]=0xFFFFFFFF, W^23[0]=0xFFFFFFFF contribute (W-1)*c[k] to word 0.
    u128 r[13]{}; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    constexpr u128 Wm1 = 0xffffffffULL;  // W-1
    constexpr u128 Wm2 = 0xfffffffeULL;  // W-2
    constexpr u128 Wm3 = 0xfffffffdULL;  // W-3

    r[0]  = c[0]  + c12 + c20 + Wm1*c22 + Wm1*c23; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    r[1]  = c[1]  + Wm1*c12 + c13 + Wm1*c20 + c21 + c22; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    r[2]  = c[2]  + Wm1*c12 + Wm1*c13 + c14 + Wm1*c20 + Wm1*c21 + c23; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    r[3]  = c[3]  + Wm1*c13 + Wm1*c14 + c15 + Wm1*c21 + Wm2*c22 + Wm1*c23; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    r[4]  = c[4]  + c12 + Wm1*c14 + Wm1*c15 + c16 + c20 + Wm1*c22 + Wm3*c23; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    r[5]  = c[5]  + c13 + Wm1*c15 + Wm1*c16 + c17 + c21 + c22; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    r[6]  = c[6]  + c14 + Wm1*c16 + Wm1*c17 + c18 + c22 + static_cast<u128>(2)*c23; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    r[7]  = c[7]  + c15 + Wm1*c17 + Wm1*c18 + c19 + c23; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    r[8]  = c[8]  + c16 + Wm1*c18 + Wm1*c19 + c20; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    r[9]  = c[9]  + c17 + Wm1*c19 + Wm1*c20 + c21; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    r[10] = c[10] + c18 + Wm1*c20 + Wm1*c21 + c22; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    r[11] = c[11] + c19 + Wm1*c21 + Wm1*c22 + c23; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)

    // Carry propagate (each r[j] < 2^68 before propagation; u128 handles it cleanly).
    for (int i = 0; i < 11; ++i) {
        r[i + 1] += r[i] >> 32U; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        r[i] &= 0xffffffffULL; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    }
    r[12] = r[11] >> 32U; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    r[11] &= 0xffffffffULL; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)

    // Overflow reduction: 2^384 ≡ W^0 − W^1 − W^2 + W^4 (mod p384) using carry-split.
    // 2^384 mod p384 word decomposition: [1, W-1, W-1, 0, 1, 0, ...].
    // Applying carry-split on the W-1 terms yields: r[0]+=ov; r[1]-=ov; r[3]+=ov; r[4]+=ov.
    // After initial carry propagation r[12] ≤ 2^33, so 2 passes suffice.
    // Use signed __int128 for the overflow passes so negation works correctly.
    int64_t s[13]{}; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    for (int i = 0; i <= 12; ++i) {
        s[i] = static_cast<int64_t>(r[i]);
    }
    for (int pass = 0; pass < 2; ++pass) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        const int64_t ov = s[12];
        s[12] = 0;
        s[0] += ov;
        s[1] -= ov;
        s[3] += ov;
        s[4] += ov;
        for (int i = 0; i < 11; ++i) {
            s[i + 1] += s[i] >> 32; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers,hicpp-signed-bitwise)
            s[i] &= 0xffffffffLL; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers,hicpp-signed-bitwise)
        }
        s[12] = s[11] >> 32; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers,hicpp-signed-bitwise)
        s[11] &= 0xffffffffLL; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers,hicpp-signed-bitwise)
    }

    Fe384 result{{
        static_cast<uint64_t>(s[0])  | (static_cast<uint64_t>(s[1])  << 32U),
        static_cast<uint64_t>(s[2])  | (static_cast<uint64_t>(s[3])  << 32U),
        static_cast<uint64_t>(s[4])  | (static_cast<uint64_t>(s[5])  << 32U),
        static_cast<uint64_t>(s[6])  | (static_cast<uint64_t>(s[7])  << 32U),
        static_cast<uint64_t>(s[8])  | (static_cast<uint64_t>(s[9])  << 32U),
        static_cast<uint64_t>(s[10]) | (static_cast<uint64_t>(s[11]) << 32U),
    }};

    result = fe384_reduce_once(result, 0U);
    result = fe384_reduce_once(result, 0U);
    result = fe384_reduce_once(result, 0U);
    result = fe384_reduce_once(result, 0U);
    return result;
}

[[nodiscard]]
static inline auto fe384_mul(const Fe384& a, const Fe384& b) noexcept -> Fe384 {
    using u128 = unsigned __int128;

    // 6×6 row-by-row multiply: 36 u64×u64 multiply-accumulates vs the old 12×12=144 u32 ones.
    // Each row carries out so every c[k] stays in [0, 2^64).
    uint64_t c[12]{}; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    for (int i = 0; i < 6; ++i) {
        uint64_t carry = 0;
        for (int j = 0; j < 6; ++j) {
            const u128 t = static_cast<u128>(a.v[i]) * b.v[j] + c[i + j] + carry;
            c[i + j] = static_cast<uint64_t>(t);
            carry    = static_cast<uint64_t>(t >> 64U);
        }
        c[i + 6] = carry;
    }

    // Expand 12 × 64-bit words to 24 × 32-bit words for the existing Solinas path.
    uint32_t c32[24]; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    for (int i = 0; i < 12; ++i) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        c32[2 * i]     = static_cast<uint32_t>(c[i]);
        c32[2 * i + 1] = static_cast<uint32_t>(c[i] >> 32U);
    }
    return fe384_solinas(c32);
}

[[nodiscard]]
static inline auto fe384_sqr(const Fe384& a) noexcept -> Fe384 {
    return fe384_mul(a, a);
}

// -----------------------------------------------------------------------
// Predicates.
// -----------------------------------------------------------------------

[[nodiscard]]
static inline auto fe384_is_zero(const Fe384& a) noexcept -> bool {
    return (a.v[0] | a.v[1] | a.v[2] | a.v[3] | a.v[4] | a.v[5]) == 0U;
}

[[nodiscard]]
static inline auto fe384_equal(const Fe384& a, const Fe384& b) noexcept -> bool {
    return ((a.v[0] ^ b.v[0]) | (a.v[1] ^ b.v[1]) | (a.v[2] ^ b.v[2]) |
            (a.v[3] ^ b.v[3]) | (a.v[4] ^ b.v[4]) | (a.v[5] ^ b.v[5])) == 0U;
}

// -----------------------------------------------------------------------
// Field inversion: a^(p−2) mod p.
// -----------------------------------------------------------------------

// Compute a^(p-2) mod p384 using an addition chain.
//
// p-2 bit structure (MSB = bit 383 first):
//   bits 383..129: 255 ones
//   bit 128:       0
//   bits 127..96:  32 ones
//   bits 95..32:   64 zeros
//   bits 31..2:    30 ones
//   bit 1:         0
//   bit 0:         1
//
// Cost: ~457 field multiplications (vs ~702 for generic square-and-multiply).
[[nodiscard]]
static inline auto fe384_invert(const Fe384& a) noexcept -> Fe384 {
    // Build a^(2^k-1) for k = 2, 4, 8, 16, 32.
    const Fe384 p2 = fe384_mul(fe384_sqr(a), a);          // a^3 = a^(2^2-1)
    Fe384 t = fe384_sqr(fe384_sqr(p2));                    // a^12
    const Fe384 p4 = fe384_mul(t, p2);                     // a^15 = a^(2^4-1)
    t = p4;
    for (int i = 0; i < 4; ++i) { t = fe384_sqr(t); }     // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    const Fe384 p8 = fe384_mul(t, p4);                     // a^(2^8-1)
    t = p8;
    for (int i = 0; i < 8; ++i) { t = fe384_sqr(t); }     // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    const Fe384 p16 = fe384_mul(t, p8);                    // a^(2^16-1)
    t = p16;
    for (int i = 0; i < 16; ++i) { t = fe384_sqr(t); }    // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    const Fe384 p32 = fe384_mul(t, p16);                   // a^(2^32-1)

    // Bits 383..129: 255 ones = 7 blocks of 32 ones + 31 individual ones.
    Fe384 acc = p32;  // first 32 ones
    for (int blk = 0; blk < 6; ++blk) {  // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        for (int i = 0; i < 32; ++i) { acc = fe384_sqr(acc); }  // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        acc = fe384_mul(acc, p32);
    }
    for (int i = 0; i < 31; ++i) {  // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        acc = fe384_sqr(acc);
        acc = fe384_mul(acc, a);
    }
    // acc = a^(2^255-1)

    // Bit 128 = 0:
    acc = fe384_sqr(acc);

    // Bits 127..96: 32 ones.
    for (int i = 0; i < 32; ++i) { acc = fe384_sqr(acc); }  // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    acc = fe384_mul(acc, p32);

    // Bits 95..32: 64 zeros.
    for (int i = 0; i < 64; ++i) { acc = fe384_sqr(acc); }  // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)

    // Bits 31..2: 30 ones.
    for (int i = 0; i < 30; ++i) {  // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        acc = fe384_sqr(acc);
        acc = fe384_mul(acc, a);
    }

    // Bit 1 = 0:
    acc = fe384_sqr(acc);

    // Bit 0 = 1:
    acc = fe384_sqr(acc);
    acc = fe384_mul(acc, a);

    return acc;
}

}  // namespace arm_asm::detail
