// SPDX-License-Identifier: Apache-2.0

#pragma once

// GHASH for AES-256-GCM using Intel PCLMULQDQ.
//
// GHASH is multiplication in GF(2¹²⁸) with the irreducible polynomial
// x¹²⁸ + x⁷ + x² + x + 1, followed by XOR-accumulation.
//
// GCM data is big-endian (MSB-first). PCLMULQDQ operates on 64-bit limbs
// stored in little-endian register order. We reconcile this by byte-reversing
// each 16-byte block on load/store (swapping bytes 0↔15, 1↔14, …).  After
// that byte-swap the polynomial bit order matches what PCLMULQDQ expects.
//
// 128-bit carry-less multiply a * b → 256-bit (lo, hi) using four PCLMULQDQ:
//   lo_lo = lo(a) * lo(b)   [clmul 0x00]
//   hi_hi = hi(a) * hi(b)   [clmul 0x11]
//   mid   = lo(a)*hi(b) ^ hi(a)*lo(b)  [clmul 0x10 ^ clmul 0x01]
//   lo  = lo_lo ^ (mid << 64)
//   hi  = hi_hi ^ (mid >> 64)
//
// Reduction modulo x¹²⁸ + x⁷ + x² + x + 1 (CLMUL-WP Algorithm 5):
//   1. Shift 256-bit product one bit left (gcm_shift).
//   2. Reduce low 128 bits of product (gcm_reduce): multiply by x⁶³+x⁶²+x⁵⁷.
//   3. Mix (gcm_mix): complete the Montgomery-style second reduction pass.
//   Final 128-bit result = mix(reduce(lo)) ^ hi.
//
// This follows Intel CLMUL Whitepaper Algorithm 5 exactly, matching MbedTLS.

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <immintrin.h>

#include "defs.hpp"


namespace ia_asm::detail {

// Load a 16-byte GCM block and byte-reverse it for PCLMULQDQ polynomial order.
[[gnu::target("pclmul,ssse3")]]
static inline __m128i ghash_load(const uint8_t* block) noexcept {
    const __m128i bswap = _mm_set_epi8( // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
    );
    return _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(block)), bswap);
}

[[gnu::target("pclmul,ssse3")]]
static inline void ghash_store(uint8_t* out, __m128i v) noexcept {
    const __m128i bswap = _mm_set_epi8( // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
    );
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out), _mm_shuffle_epi8(v, bswap));
}


// 128-bit carry-less multiply: a * b → lo:hi (256-bit result).
[[gnu::target("pclmul,ssse3")]]
static inline void ghash_clmul256(__m128i a, __m128i b,
                                   __m128i& lo, __m128i& hi) noexcept {
    const __m128i lo_lo = _mm_clmulepi64_si128(a, b, 0x00); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    const __m128i hi_hi = _mm_clmulepi64_si128(a, b, 0x11); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    __m128i       mid   = _mm_xor_si128(
                              _mm_clmulepi64_si128(a, b, 0x10), // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
                              _mm_clmulepi64_si128(a, b, 0x01)  // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
                          );
    const __m128i mid_lo = _mm_slli_si128(mid, 8); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    const __m128i mid_hi = _mm_srli_si128(mid, 8); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    lo = _mm_xor_si128(lo_lo, mid_lo);
    hi = _mm_xor_si128(hi_hi, mid_hi);
}


// CLMUL-WP Algorithm 5 Step 1: shift the 256-bit product one bit left.
[[gnu::target("pclmul,ssse3")]]
static inline void ghash_shift(__m128i& lo, __m128i& hi) noexcept {
    const __m128i lo_hi = _mm_srli_epi64(lo, 63); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    const __m128i hi_hi = _mm_srli_epi64(hi, 63); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    // Carry bit: bit 63 of lo's high 64-bit lane propagates into lo bit of hi.
    const __m128i carry = _mm_srli_si128(lo_hi, 8); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    const __m128i lo_hi_shifted = _mm_slli_si128(lo_hi, 8); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    lo = _mm_or_si128(_mm_slli_epi64(lo, 1), lo_hi_shifted); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    hi = _mm_or_si128(_mm_slli_epi64(hi, 1), // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
                      _mm_or_si128(_mm_slli_si128(hi_hi, 8), carry)); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
}


// CLMUL-WP Algorithm 5 Step 2: first reduction pass on the low 128 bits.
[[gnu::target("pclmul,ssse3")]]
static inline __m128i ghash_reduce(__m128i xx) noexcept {
    const __m128i aa = _mm_slli_epi64(xx, 63); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    const __m128i bb = _mm_slli_epi64(xx, 62); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    const __m128i cc = _mm_slli_epi64(xx, 57); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    const __m128i dd = _mm_slli_si128( // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
                           _mm_xor_si128(_mm_xor_si128(aa, bb), cc), 8);
    return _mm_xor_si128(dd, xx);
}


// CLMUL-WP Algorithm 5 Steps 3-4: second reduction pass (mix).
[[gnu::target("pclmul,ssse3")]]
static inline __m128i ghash_mix(__m128i dx) noexcept {
    const __m128i ee = _mm_srli_epi64(dx, 1); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    const __m128i ff = _mm_srli_epi64(dx, 2); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    const __m128i gg = _mm_srli_epi64(dx, 7); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    const __m128i eh = _mm_slli_epi64(dx, 63); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    const __m128i fh = _mm_slli_epi64(dx, 62); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    const __m128i gh = _mm_slli_epi64(dx, 57); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    const __m128i hh = _mm_srli_si128(_mm_xor_si128(_mm_xor_si128(eh, fh), gh), 8); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    return _mm_xor_si128(_mm_xor_si128(_mm_xor_si128(_mm_xor_si128(ee, ff), gg), hh), dx);
}


// GHASH context.
struct GhashCtx {
    __m128i acc; // NOLINT(misc-non-private-member-variables-in-classes)
    __m128i H;   // NOLINT(misc-non-private-member-variables-in-classes)

    [[gnu::target("pclmul,ssse3")]]
    void init(const uint8_t* H_block) noexcept {
        acc = _mm_setzero_si128();
        H   = ghash_load(H_block);
    }

    [[gnu::target("pclmul,ssse3")]]
    void update(const uint8_t* block) noexcept {
        const __m128i b = ghash_load(block);
        const __m128i x = _mm_xor_si128(acc, b);
        __m128i lo{};
        __m128i hi{};
        ghash_clmul256(x, H, lo, hi);
        ghash_shift(lo, hi);
        const __m128i dx = ghash_reduce(lo);
        const __m128i xh = ghash_mix(dx);
        acc = _mm_xor_si128(xh, hi);
    }

    [[gnu::target("pclmul,ssse3")]]
    void update_partial(const uint8_t* data, std::size_t len) noexcept {
        std::array<uint8_t, 16> buf{}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        std::memcpy(buf.data(), data, len);
        update(buf.data());
    }

    [[gnu::target("pclmul,ssse3")]]
    void finish(uint8_t* out) const noexcept {
        ghash_store(out, acc);
    }
};

}  // namespace ia_asm::detail
