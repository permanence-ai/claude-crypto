// SPDX-License-Identifier: Apache-2.0

#pragma once

// P-256 (secp256r1) prime field arithmetic.
//
// Field prime: p = 2^256 − 2^224 + 2^192 + 2^96 − 1
// Represented as 4 × uint64_t little-endian 64-bit limbs, always in [0, p-1].
//
// Multiplication uses the Solinas fast reduction from FIPS 186-4 App. D.1.2.3.
// Per-word accumulation (word w covers bits [32w, 32w+31]):
//
//   r[0] = c[0] + c[8]  + c[9]  − c[11] − c[12] − c[13] − c[14]
//   r[1] = c[1] + c[9]  + c[10] − c[12] − c[13] − c[14] − c[15]
//   r[2] = c[2] + c[10] + c[11] − c[13] − c[14] − c[15]
//   r[3] = c[3] + 2·c[11] + 2·c[12] + c[13] − c[14] − c[15] − c[8]  − c[9]
//   r[4] = c[4] + 2·c[12] + 2·c[13] + c[14] − c[15] − 2·c[10] − c[9]
//   r[5] = c[5] + 2·c[13] + 2·c[14] + c[15] − c[10] − c[11]
//   r[6] = c[6] + 3·c[14] + 2·c[15] + c[13] − c[8]  − c[9]
//   r[7] = c[7] + 3·c[15] + c[8]  − c[10] − c[11] − c[12] − c[13]
//
// Overflow: 2^256 ≡ 2^224 − 2^192 − 2^96 + 1 (mod p),
// i.e. overflow word ov adds to r[0], r[7] and subtracts from r[3], r[6].
//
// All arithmetic is constant-time with respect to field element inputs.

#include <cstddef>
#include <cstdint>
#include <cstring>


namespace arm_asm::detail {


struct Fe256 {
    uint64_t v[4]; // NOLINT(misc-non-private-member-variables-in-classes)
};

static constexpr Fe256 fe256_zero = {{0ULL, 0ULL, 0ULL, 0ULL}};
static constexpr Fe256 fe256_one  = {{1ULL, 0ULL, 0ULL, 0ULL}};

// p in 4 × 64-bit LE limbs.
static constexpr Fe256 fe256_p = {{
    0xffffffffffffffffULL,
    0x00000000ffffffffULL,
    0x0000000000000000ULL,
    0xffffffff00000001ULL,
}};

// -----------------------------------------------------------------------
// Byte encoding (big-endian, matching SEC 1 / PSA wire format).
// -----------------------------------------------------------------------

[[nodiscard]]
static inline auto fe256_from_bytes(  // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    const uint8_t b[32]) noexcept -> Fe256
{
    Fe256 r{};
    for (int i = 0; i < 4; ++i) {
        const uint8_t* p = b + (static_cast<std::ptrdiff_t>(3 - i) * 8); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        r.v[i] =
            (static_cast<uint64_t>(p[0]) << 56U) | (static_cast<uint64_t>(p[1]) << 48U) |
            (static_cast<uint64_t>(p[2]) << 40U) | (static_cast<uint64_t>(p[3]) << 32U) |
            (static_cast<uint64_t>(p[4]) << 24U) | (static_cast<uint64_t>(p[5]) << 16U) |
            (static_cast<uint64_t>(p[6]) <<  8U) |  static_cast<uint64_t>(p[7]);
    }
    return r;
}

static inline void fe256_to_bytes(  // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    const Fe256& a, uint8_t b[32]) noexcept
{
    for (int i = 0; i < 4; ++i) {
        uint8_t* p = b + (static_cast<std::ptrdiff_t>(3 - i) * 8); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
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
// Internal reduction helpers.
// -----------------------------------------------------------------------

// Constant-time select: returns (a & mask) | (b & ~mask).
[[nodiscard]]
static inline auto fe256_ct_select(
    const Fe256& a, const Fe256& b, uint64_t mask) noexcept -> Fe256
{
    return Fe256{{
        (a.v[0] & mask) | (b.v[0] & ~mask),
        (a.v[1] & mask) | (b.v[1] & ~mask),
        (a.v[2] & mask) | (b.v[2] & ~mask),
        (a.v[3] & mask) | (b.v[3] & ~mask),
    }};
}

// Compute out = a − p; return borrow (1 if a < p, 0 if a ≥ p).
[[nodiscard]]
static inline auto fe256_sub_p(const Fe256& a, Fe256& out) noexcept -> uint64_t {
    constexpr uint64_t p0 = 0xffffffffffffffffULL;
    constexpr uint64_t p1 = 0x00000000ffffffffULL;
    constexpr uint64_t p2 = 0x0000000000000000ULL;
    constexpr uint64_t p3 = 0xffffffff00000001ULL;
    using u128 = unsigned __int128;
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
    return static_cast<uint64_t>(t >> 127U);
}

// Conditionally subtract p. If overflow || a ≥ p, return a − p; else a.
[[nodiscard]]
static inline auto fe256_reduce_once(const Fe256& a, uint64_t overflow) noexcept -> Fe256 {
    Fe256 sub{};
    const uint64_t borrow = fe256_sub_p(a, sub);
    const uint64_t use_sub = overflow | (1U - borrow);
    const uint64_t mask = 0U - use_sub;
    return fe256_ct_select(sub, a, mask);
}

// -----------------------------------------------------------------------
// Field addition and subtraction.
// -----------------------------------------------------------------------

[[nodiscard]]
static inline auto fe256_add(const Fe256& a, const Fe256& b) noexcept -> Fe256 {
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
    return fe256_reduce_once(r, static_cast<uint64_t>(t >> 64U));
}

[[nodiscard]]
static inline auto fe256_sub(const Fe256& a, const Fe256& b) noexcept -> Fe256 {
    using u128 = unsigned __int128;
    constexpr uint64_t p0 = 0xffffffffffffffffULL;
    constexpr uint64_t p1 = 0x00000000ffffffffULL;
    constexpr uint64_t p2 = 0x0000000000000000ULL;
    constexpr uint64_t p3 = 0xffffffff00000001ULL;
    auto t = static_cast<u128>(a.v[0]) - b.v[0];
    Fe256 r{};
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
    // Conditionally add p to restore [0, p-1] range.
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
    return r;
}

// −a mod p  (= p − a, reduced to 0 when a == 0).
[[nodiscard]]
static inline auto fe256_neg(const Fe256& a) noexcept -> Fe256 {
    using u128 = unsigned __int128;
    constexpr uint64_t p0 = 0xffffffffffffffffULL;
    constexpr uint64_t p1 = 0x00000000ffffffffULL;
    constexpr uint64_t p2 = 0x0000000000000000ULL;
    constexpr uint64_t p3 = 0xffffffff00000001ULL;
    auto t = static_cast<u128>(p0) - a.v[0];
    Fe256 r{};
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
    // When a == 0, result is p; fe256_reduce_once brings it to 0.
    return fe256_reduce_once(r, 0U);
}

// -----------------------------------------------------------------------
// Field multiplication via Solinas fast reduction.
// -----------------------------------------------------------------------

// Compute the 512-bit product a × b as 16 × uint32_t words (word 0 = LSW).
static inline void fe256_mul_raw( // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    uint32_t c[16], const Fe256& a, const Fe256& b) noexcept
{
    uint32_t a32[8]; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    uint32_t b32[8]; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    for (int i = 0; i < 4; ++i) {
        a32[2U * static_cast<std::size_t>(i)]     = static_cast<uint32_t>(a.v[i]);
        a32[(2U * static_cast<std::size_t>(i)) + 1] = static_cast<uint32_t>(a.v[i] >> 32U);
        b32[2U * static_cast<std::size_t>(i)]     = static_cast<uint32_t>(b.v[i]);
        b32[(2U * static_cast<std::size_t>(i)) + 1] = static_cast<uint32_t>(b.v[i] >> 32U);
    }
    using u128 = unsigned __int128;
    u128 tmp[16]{}; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    for (int i = 0; i < 8; ++i) {
        for (int j = 0; j < 8; ++j) {
            tmp[static_cast<std::size_t>(i + j)] += static_cast<u128>(a32[i]) * b32[j];
        }
    }
    uint64_t carry = 0;
    for (int i = 0; i < 16; ++i) {
        const u128 t = tmp[i] + carry;
        c[i] = static_cast<uint32_t>(t);
        carry = static_cast<uint64_t>(t >> 32U);
    }
}

// Apply Solinas fast reduction: 16 × uint32_t → Fe256 in [0, p-1].
[[nodiscard]]
static inline auto fe256_solinas( // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    const uint32_t c[16]) noexcept -> Fe256
{
    // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    int64_t r[9]{}; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    r[0] = static_cast<int64_t>(c[0]) + c[8] + c[9] - c[11] - c[12] - c[13] - c[14];
    r[1] = static_cast<int64_t>(c[1]) + c[9] + c[10] - c[12] - c[13] - c[14] - c[15];
    r[2] = static_cast<int64_t>(c[2]) + c[10] + c[11] - c[13] - c[14] - c[15];
    r[3] = static_cast<int64_t>(c[3]) + (2*static_cast<int64_t>(c[11])) + (2*static_cast<int64_t>(c[12]))
         + c[13] - c[15] - c[8] - c[9];
    r[4] = static_cast<int64_t>(c[4]) + (2*static_cast<int64_t>(c[12])) + (2*static_cast<int64_t>(c[13]))
         + c[14] - c[9] - c[10];
    r[5] = static_cast<int64_t>(c[5]) + (2*static_cast<int64_t>(c[13])) + (2*static_cast<int64_t>(c[14]))
         + c[15] - c[10] - c[11];
    r[6] = static_cast<int64_t>(c[6]) + (3*static_cast<int64_t>(c[14])) + (2*static_cast<int64_t>(c[15]))
         + c[13] - c[8] - c[9];
    r[7] = static_cast<int64_t>(c[7]) + (3*static_cast<int64_t>(c[15]))
         + c[8] - c[10] - c[11] - c[12] - c[13];

    // Carry-propagate to normalise each word to [0, 2^32-1].
    // Arithmetic right-shift on int64_t is intentional: negative words carry a signed borrow.
    for (int i = 0; i < 7; ++i) {
        r[i + 1] += r[i] >> 32; // NOLINT(hicpp-signed-bitwise)
        r[i] &= 0xffffffffLL; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers,hicpp-signed-bitwise)
    }
    r[8] = r[7] >> 32; // NOLINT(hicpp-signed-bitwise)
    r[7] &= 0xffffffffLL; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers,hicpp-signed-bitwise)

    // Reduce overflow word twice (always, for constant time).
    // 2^256 ≡ 2^224 − 2^192 − 2^96 + 1 (mod p)
    // → ov·2^256 mod p adds ov to words 0, 7 and subtracts from words 3, 6.
    for (int pass = 0; pass < 2; ++pass) {
        const int64_t ov = r[8];
        r[8] = 0;
        r[0] += ov; r[3] -= ov; r[6] -= ov; r[7] += ov;
        for (int i = 0; i < 7; ++i) {
            r[i + 1] += r[i] >> 32; // NOLINT(hicpp-signed-bitwise)
            r[i] &= 0xffffffffLL; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers,hicpp-signed-bitwise)
        }
        r[8] = r[7] >> 32; // NOLINT(hicpp-signed-bitwise)
        r[7] &= 0xffffffffLL; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers,hicpp-signed-bitwise)
    }

    // Pack 8 × 32-bit into 4 × 64-bit LE.
    Fe256 result{{
        static_cast<uint64_t>(r[0]) | (static_cast<uint64_t>(r[1]) << 32U),
        static_cast<uint64_t>(r[2]) | (static_cast<uint64_t>(r[3]) << 32U),
        static_cast<uint64_t>(r[4]) | (static_cast<uint64_t>(r[5]) << 32U),
        static_cast<uint64_t>(r[6]) | (static_cast<uint64_t>(r[7]) << 32U),
    }};

    // Result is in [0, 4p) after reduction; up to 4 conditional subtracts needed.
    result = fe256_reduce_once(result, 0U);
    result = fe256_reduce_once(result, 0U);
    result = fe256_reduce_once(result, 0U);
    result = fe256_reduce_once(result, 0U);
    return result;
}

[[nodiscard]]
static inline auto fe256_mul(const Fe256& a, const Fe256& b) noexcept -> Fe256 {
    uint32_t c[16]; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    fe256_mul_raw(c, a, b);
    return fe256_solinas(c);
}

[[nodiscard]]
static inline auto fe256_sqr(const Fe256& a) noexcept -> Fe256 {
    return fe256_mul(a, a);
}

// -----------------------------------------------------------------------
// Predicates.
// -----------------------------------------------------------------------

[[nodiscard]]
static inline auto fe256_is_zero(const Fe256& a) noexcept -> bool {
    return (a.v[0] | a.v[1] | a.v[2] | a.v[3]) == 0U;
}

[[nodiscard]]
static inline auto fe256_equal(const Fe256& a, const Fe256& b) noexcept -> bool {
    return ((a.v[0] ^ b.v[0]) | (a.v[1] ^ b.v[1]) |
            (a.v[2] ^ b.v[2]) | (a.v[3] ^ b.v[3])) == 0U;
}

// -----------------------------------------------------------------------
// Field inversion: a^(p−2) mod p.
// The exponent p−2 is a public constant, so branches on its bits do not
// leak information about the secret input a.
// -----------------------------------------------------------------------

[[nodiscard]]
static inline auto fe256_invert(const Fe256& a) noexcept -> Fe256 {
    // p−2 = 0xffffffff00000001 00000000ffffffff 0000000000000000 fffffffffffffffd
    static constexpr uint64_t exp[4] = { // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
        0xfffffffffffffffdULL,  // bits  0..63   (p-2 low word)
        0x00000000ffffffffULL,  // bits 64..127
        0x0000000000000000ULL,  // bits 128..191
        0xffffffff00000001ULL,  // bits 192..255 (p-2 high word)
    };
    Fe256 result = fe256_one;
    for (int word = 3; word >= 0; --word) {
        for (int bit = 63; bit >= 0; --bit) {
            result = fe256_sqr(result);
            if (((exp[word] >> static_cast<unsigned>(bit)) & 1U) != 0U) {
                result = fe256_mul(result, a);
            }
        }
    }
    return result;
}

}  // namespace arm_asm::detail
