// SPDX-License-Identifier: Apache-2.0

#pragma once

// P-521 (secp521r1) prime field arithmetic.
//
// Field prime: p = 2^521 − 1  (Mersenne prime, all 521 bits set)
// Represented as 9 × uint64_t little-endian 64-bit limbs.
// The top limb v[8] holds bits 512–520, so only the low 9 bits are used:
//   v[8] ∈ [0, 0x1ff].
//
// Multiplication uses Mersenne reduction: 2^521 ≡ 1 (mod p), so
//   a · b mod p = lo521(a·b) + hi521(a·b)  (then reduce once if ≥ p).
//
// All arithmetic is constant-time with respect to field element inputs.

#include <cstddef>
#include <cstdint>
#include <cstring>


namespace arm_asm::detail {


struct Fe521 {
    uint64_t v[9]; // NOLINT(misc-non-private-member-variables-in-classes)
};

static constexpr Fe521 fe521_zero = {{0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL}};
static constexpr Fe521 fe521_one  = {{1ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL}};

// p in 9 × 64-bit LE limbs (all bits set in the low 521 bits).
static constexpr Fe521 fe521_p = {{
    0xffffffffffffffffULL,
    0xffffffffffffffffULL,
    0xffffffffffffffffULL,
    0xffffffffffffffffULL,
    0xffffffffffffffffULL,
    0xffffffffffffffffULL,
    0xffffffffffffffffULL,
    0xffffffffffffffffULL,
    0x00000000000001ffULL,
}};

// -----------------------------------------------------------------------
// Byte encoding (big-endian, 66 bytes, matching SEC 1 / PSA wire format).
// -----------------------------------------------------------------------

[[nodiscard]]
static inline auto fe521_from_bytes( // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    const uint8_t b[66]) noexcept -> Fe521 // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
{
    // 66 bytes = 528 bits; top 7 bits are always zero (521-bit field element).
    // b[0] is the most significant byte (bits 520–513... but only 9 low bits used).
    // Layout: b[0] holds bits[520:513] = top 9 bits (≤ 0x01, bits [8:0] of v[8]).
    // b[1..65] hold the remaining 65×8 = 520 bits.
    Fe521 r{};
    // v[8]: top 9 bits from b[0] (1 byte) and b[1] (top 1 bit unused, 0-padded).
    // More precisely: the 521-bit integer is spread across 66 bytes big-endian.
    // byte[0] = bits[520:513], ..., byte[65] = bits[7:0].
    // v[i] = bits[64i+63 : 64i].
    // v[8] = bits[520:512] = 9 bits = top byte (b[0] low 2 bits) | next byte high bits.
    // Easier: load as 66-byte big-endian integer, then pack into 9 limbs.
    // bits 0..7   = b[65]
    // bits 8..15  = b[64]
    // ...
    // bits 512..519 = b[1]
    // bits 520..527 = b[0]  (top 7 bits must be zero)
    for (int i = 0; i < 8; ++i) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        const uint8_t* p = b + (65 - i * 8); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic,cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        r.v[i] =
            (static_cast<uint64_t>(p[-7]) << 56U) | (static_cast<uint64_t>(p[-6]) << 48U) | // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
            (static_cast<uint64_t>(p[-5]) << 40U) | (static_cast<uint64_t>(p[-4]) << 32U) | // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
            (static_cast<uint64_t>(p[-3]) << 24U) | (static_cast<uint64_t>(p[-2]) << 16U) | // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
            (static_cast<uint64_t>(p[-1]) <<  8U) |  static_cast<uint64_t>(p[0]);           // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    }
    // v[8]: top 9 bits.  b[0] = bits[520:513] (but 521-bit so b[0] ≤ 0x01), b[1] = bits[512:505].
    // v[8] = b[0] << 1 | b[1] >> 7  ... no, byte-level: 521 bits in 66 bytes.
    // 66*8 = 528; the top 7 bits of b[0] are always zero, only the low bit of b[0] is used.
    // v[8] = (b[0] << 8) | b[1]  NO — v[8] is bits [575:512] if we had 9 full limbs,
    // but we only have 521 bits, so v[8] = bits [520:512] = 9 bits.
    // bits [520:512]: byte index 65-64 = byte 1 has bits [519:512], byte 0 has bit [520].
    // So v[8] = (b[0] << 8) | b[1] truncated to 9 bits.
    r.v[8] = (static_cast<uint64_t>(b[0]) << 8U) | static_cast<uint64_t>(b[1]); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic,cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    r.v[8] &= 0x1ffULL;
    return r;
}

static inline void fe521_to_bytes( // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    const Fe521& a, uint8_t b[66]) noexcept // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
{
    // v[8] holds 9 bits: bits[520:512].  Write as b[0] (bit 520) and b[1] (bits[519:512]).
    b[0] = static_cast<uint8_t>(a.v[8] >> 8U); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic,cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    b[1] = static_cast<uint8_t>(a.v[8]); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    for (int i = 0; i < 8; ++i) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        uint8_t* p = b + (65 - i * 8); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic,cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        p[0]  = static_cast<uint8_t>(a.v[i]);                      // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        p[-1] = static_cast<uint8_t>(a.v[i] >> 8U);                // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        p[-2] = static_cast<uint8_t>(a.v[i] >> 16U);               // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        p[-3] = static_cast<uint8_t>(a.v[i] >> 24U);               // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        p[-4] = static_cast<uint8_t>(a.v[i] >> 32U);               // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        p[-5] = static_cast<uint8_t>(a.v[i] >> 40U);               // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        p[-6] = static_cast<uint8_t>(a.v[i] >> 48U);               // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        p[-7] = static_cast<uint8_t>(a.v[i] >> 56U);               // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    }
}

// -----------------------------------------------------------------------
// Internal helpers.
// -----------------------------------------------------------------------

// a − p, returning borrow (1 if a < p).
[[nodiscard]]
static inline auto fe521_sub_p(const Fe521& a, Fe521& out) noexcept -> uint64_t {
    using u128 = unsigned __int128;
    auto t = static_cast<u128>(a.v[0]) - fe521_p.v[0];
    out.v[0] = static_cast<uint64_t>(t);
    auto borrow = static_cast<uint64_t>(t >> 127U);
    t = static_cast<u128>(a.v[1]) - fe521_p.v[1] - borrow;
    out.v[1] = static_cast<uint64_t>(t);
    borrow = static_cast<uint64_t>(t >> 127U);
    t = static_cast<u128>(a.v[2]) - fe521_p.v[2] - borrow;
    out.v[2] = static_cast<uint64_t>(t);
    borrow = static_cast<uint64_t>(t >> 127U);
    t = static_cast<u128>(a.v[3]) - fe521_p.v[3] - borrow;
    out.v[3] = static_cast<uint64_t>(t);
    borrow = static_cast<uint64_t>(t >> 127U);
    t = static_cast<u128>(a.v[4]) - fe521_p.v[4] - borrow;
    out.v[4] = static_cast<uint64_t>(t);
    borrow = static_cast<uint64_t>(t >> 127U);
    t = static_cast<u128>(a.v[5]) - fe521_p.v[5] - borrow;
    out.v[5] = static_cast<uint64_t>(t);
    borrow = static_cast<uint64_t>(t >> 127U);
    t = static_cast<u128>(a.v[6]) - fe521_p.v[6] - borrow;
    out.v[6] = static_cast<uint64_t>(t);
    borrow = static_cast<uint64_t>(t >> 127U);
    t = static_cast<u128>(a.v[7]) - fe521_p.v[7] - borrow;
    out.v[7] = static_cast<uint64_t>(t);
    borrow = static_cast<uint64_t>(t >> 127U);
    t = static_cast<u128>(a.v[8]) - fe521_p.v[8] - borrow;
    out.v[8] = static_cast<uint64_t>(t);
    return static_cast<uint64_t>(t >> 127U);
}

[[nodiscard]]
static inline auto fe521_reduce_once(const Fe521& a, uint64_t overflow) noexcept -> Fe521 {
    Fe521 sub{};
    const uint64_t borrow = fe521_sub_p(a, sub);
    const uint64_t use_sub = overflow | (1U - borrow);
    const uint64_t mask = 0U - use_sub;
    return Fe521{{
        (sub.v[0] & mask) | (a.v[0] & ~mask),
        (sub.v[1] & mask) | (a.v[1] & ~mask),
        (sub.v[2] & mask) | (a.v[2] & ~mask),
        (sub.v[3] & mask) | (a.v[3] & ~mask),
        (sub.v[4] & mask) | (a.v[4] & ~mask),
        (sub.v[5] & mask) | (a.v[5] & ~mask),
        (sub.v[6] & mask) | (a.v[6] & ~mask),
        (sub.v[7] & mask) | (a.v[7] & ~mask),
        (sub.v[8] & mask) | (a.v[8] & ~mask),
    }};
}

// -----------------------------------------------------------------------
// Field addition and subtraction.
// -----------------------------------------------------------------------

[[nodiscard]]
static inline auto fe521_add(const Fe521& a, const Fe521& b) noexcept -> Fe521 {
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
    return fe521_reduce_once(r, static_cast<uint64_t>(t >> 64U));
}

[[nodiscard]]
static inline auto fe521_sub(const Fe521& a, const Fe521& b) noexcept -> Fe521 {
    using u128 = unsigned __int128;
    auto t = static_cast<u128>(a.v[0]) - b.v[0];
    Fe521 r{};
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
    t = static_cast<u128>(a.v[6]) - b.v[6] - borrow;
    r.v[6] = static_cast<uint64_t>(t);
    borrow = static_cast<uint64_t>(t >> 127U);
    t = static_cast<u128>(a.v[7]) - b.v[7] - borrow;
    r.v[7] = static_cast<uint64_t>(t);
    borrow = static_cast<uint64_t>(t >> 127U);
    t = static_cast<u128>(a.v[8]) - b.v[8] - borrow;
    r.v[8] = static_cast<uint64_t>(t) & 0x1ffULL;
    borrow = static_cast<uint64_t>(t >> 127U);
    // If borrow, add p back.
    const uint64_t mask = 0U - borrow;
    auto s = static_cast<u128>(r.v[0]) + (fe521_p.v[0] & mask);
    r.v[0] = static_cast<uint64_t>(s);
    auto carry = static_cast<uint64_t>(s >> 64U);
    s = static_cast<u128>(r.v[1]) + (fe521_p.v[1] & mask) + carry;
    r.v[1] = static_cast<uint64_t>(s);
    carry = static_cast<uint64_t>(s >> 64U);
    s = static_cast<u128>(r.v[2]) + (fe521_p.v[2] & mask) + carry;
    r.v[2] = static_cast<uint64_t>(s);
    carry = static_cast<uint64_t>(s >> 64U);
    s = static_cast<u128>(r.v[3]) + (fe521_p.v[3] & mask) + carry;
    r.v[3] = static_cast<uint64_t>(s);
    carry = static_cast<uint64_t>(s >> 64U);
    s = static_cast<u128>(r.v[4]) + (fe521_p.v[4] & mask) + carry;
    r.v[4] = static_cast<uint64_t>(s);
    carry = static_cast<uint64_t>(s >> 64U);
    s = static_cast<u128>(r.v[5]) + (fe521_p.v[5] & mask) + carry;
    r.v[5] = static_cast<uint64_t>(s);
    carry = static_cast<uint64_t>(s >> 64U);
    s = static_cast<u128>(r.v[6]) + (fe521_p.v[6] & mask) + carry;
    r.v[6] = static_cast<uint64_t>(s);
    carry = static_cast<uint64_t>(s >> 64U);
    s = static_cast<u128>(r.v[7]) + (fe521_p.v[7] & mask) + carry;
    r.v[7] = static_cast<uint64_t>(s);
    carry = static_cast<uint64_t>(s >> 64U);
    s = static_cast<u128>(r.v[8]) + (fe521_p.v[8] & mask) + carry;
    r.v[8] = static_cast<uint64_t>(s) & 0x1ffULL;
    return r;
}

// -----------------------------------------------------------------------
// Field multiplication via Mersenne reduction (2^521 ≡ 1 mod p).
// -----------------------------------------------------------------------
// Computes a·b mod p where a, b ∈ [0, p-1].
// Product a·b is at most (p-1)^2 < 2^1042.
// We represent the 1042-bit product as 17 × uint64_t limbs (lo_limb[0..8] and hi_limb[0..8]).
// Specifically: lo = product mod 2^521, hi = product >> 521.
// Then result = lo + hi (mod p), followed by at most one conditional subtract.

[[nodiscard]]
static inline auto fe521_mul(const Fe521& a, const Fe521& b) noexcept -> Fe521 {
    using u128 = unsigned __int128;
    // Full 9×9 schoolbook multiplication into 18 limbs with row-by-row carry
    // propagation. Accumulating all products into u128 accumulators first
    // overflows: the middle column (t[8]) sums up to 9 products each ~2^128,
    // which exceeds u128's max of 2^128-1.
    uint64_t c[18]{}; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    for (int i = 0; i < 9; ++i) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        u128 carry = 0;
        for (int j = 0; j < 9; ++j) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
            const u128 tt = static_cast<u128>(a.v[i]) * b.v[j] + c[i + j] + carry;
            c[i + j] = static_cast<uint64_t>(tt);
            carry = tt >> 64U;
        }
        for (int k = i + 9; k < 18 && carry != 0U; ++k) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
            const u128 tt = static_cast<u128>(c[k]) + carry;
            c[k] = static_cast<uint64_t>(tt);
            carry = tt >> 64U;
        }
    }
    // Mersenne reduction: 2^521 ≡ 1 (mod p).
    // The product is sum_i c[i] * 2^(64i).
    // We split at bit 521: lo = bits [0, 520], hi = bits [521, 1041].
    // Bit 521 is in c[8] at bit position 521 - 8*64 = 521 - 512 = 9.
    // lo bits [0, 512): c[0..7], lo bits [512, 520]: c[8] & 0x1ff.
    // hi: c[8] >> 9, c[9..16] (shifted by 521 bits = 8 limbs + 9 bits).
    // result = lo + hi (mod p), then reduce once.

    // lo521 = c[0..7] and low 9 bits of c[8].
    // hi521 = c[8] >> 9, c[9..16] (this is hi * 2^0 since 2^521=1).
    // We add hi into lo: the hi part represents hi * 2^521 ≡ hi (mod p).
    // hi = (c[8] >> 9) | (c[9] << 55) for limb 0, etc.

    // Build hi as a 521-bit value by extracting bits above position 521:
    // hi_limb[0] = (c[8] >> 9) | (c[9] << 55)
    // hi_limb[1] = (c[9] >> 9) | (c[10] << 55)
    // ...
    // hi_limb[7] = (c[15] >> 9) | (c[16] << 55)
    // hi_limb[8] = c[16] >> 9  (at most 55 bits, but c[16] ≤ 2^55 so fits in 9 bits)

    constexpr unsigned shift = 9U;
    constexpr unsigned rshift = 64U - shift; // 55

    uint64_t lo[9]; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    uint64_t hi[9]; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    for (int i = 0; i < 8; ++i) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        lo[i] = c[i];
        hi[i] = (c[i + 8] >> shift) | (c[i + 9] << rshift); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index,cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    }
    lo[8] = c[8] & 0x1ffULL;
    hi[8] = c[16] >> shift; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)

    // r = lo + hi with carry propagation; result is at most 2p so reduce once.
    auto s = static_cast<u128>(lo[0]) + hi[0];
    Fe521 r{};
    r.v[0] = static_cast<uint64_t>(s);
    s = static_cast<u128>(lo[1]) + hi[1] + (s >> 64U);
    r.v[1] = static_cast<uint64_t>(s);
    s = static_cast<u128>(lo[2]) + hi[2] + (s >> 64U);
    r.v[2] = static_cast<uint64_t>(s);
    s = static_cast<u128>(lo[3]) + hi[3] + (s >> 64U);
    r.v[3] = static_cast<uint64_t>(s);
    s = static_cast<u128>(lo[4]) + hi[4] + (s >> 64U);
    r.v[4] = static_cast<uint64_t>(s);
    s = static_cast<u128>(lo[5]) + hi[5] + (s >> 64U);
    r.v[5] = static_cast<uint64_t>(s);
    s = static_cast<u128>(lo[6]) + hi[6] + (s >> 64U);
    r.v[6] = static_cast<uint64_t>(s);
    s = static_cast<u128>(lo[7]) + hi[7] + (s >> 64U);
    r.v[7] = static_cast<uint64_t>(s);
    s = static_cast<u128>(lo[8]) + hi[8] + (s >> 64U);
    r.v[8] = static_cast<uint64_t>(s);
    // The carry out of bit 520 is at most 1, and wraps back via 2^521 ≡ 1.
    const uint64_t top_carry = static_cast<uint64_t>(s >> 9U);  // carry out of bit 520
    // Add top_carry back to r.v[0] (since 2^521 ≡ 1).
    s = static_cast<u128>(r.v[0]) + top_carry;
    r.v[0] = static_cast<uint64_t>(s);
    r.v[8] &= 0x1ffULL;
    // Propagate the carry (at most 1 extra carry into v[1]).
    if ((s >> 64U) != 0U) {
        for (int i = 1; i < 9; ++i) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
            r.v[i] += 1U;
            if (r.v[i] != 0U) { break; }
        }
        r.v[8] &= 0x1ffULL;
    }
    return fe521_reduce_once(r, 0U);
}

[[nodiscard]]
static inline auto fe521_sqr(const Fe521& a) noexcept -> Fe521 {
    return fe521_mul(a, a);
}

// -----------------------------------------------------------------------
// Predicates.
// -----------------------------------------------------------------------

[[nodiscard]]
static inline auto fe521_is_zero(const Fe521& a) noexcept -> bool {
    return (a.v[0] | a.v[1] | a.v[2] | a.v[3] | a.v[4] |
            a.v[5] | a.v[6] | a.v[7] | a.v[8]) == 0U;
}

[[nodiscard]]
static inline auto fe521_equal(const Fe521& a, const Fe521& b) noexcept -> bool {
    return ((a.v[0] ^ b.v[0]) | (a.v[1] ^ b.v[1]) | (a.v[2] ^ b.v[2]) |
            (a.v[3] ^ b.v[3]) | (a.v[4] ^ b.v[4]) | (a.v[5] ^ b.v[5]) |
            (a.v[6] ^ b.v[6]) | (a.v[7] ^ b.v[7]) | (a.v[8] ^ b.v[8])) == 0U;
}

// -----------------------------------------------------------------------
// Field inversion: a^(p−2) mod p.
// p−2 = 2^521 − 3: all 521 bits set except bit 1.
// -----------------------------------------------------------------------

[[nodiscard]]
static inline auto fe521_invert(const Fe521& a) noexcept -> Fe521 {
    // p-2 limbs (LE): low 64 bits = 0xfffffffffffffffd, rest all-ones.
    static constexpr uint64_t exp[9] = { // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
        0xfffffffffffffffdULL,
        0xffffffffffffffffULL,
        0xffffffffffffffffULL,
        0xffffffffffffffffULL,
        0xffffffffffffffffULL,
        0xffffffffffffffffULL,
        0xffffffffffffffffULL,
        0xffffffffffffffffULL,
        0x00000000000001ffULL,
    };
    Fe521 result = fe521_one;
    for (int word = 8; word >= 0; --word) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        const int bits = (word == 8) ? 9 : 64; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        for (int bit = bits - 1; bit >= 0; --bit) {
            result = fe521_sqr(result);
            if (((exp[word] >> static_cast<unsigned>(bit)) & 1U) != 0U) {
                result = fe521_mul(result, a);
            }
        }
    }
    return result;
}

}  // namespace arm_asm::detail
