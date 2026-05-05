/*
Copyright Permanence AI, 2026. All rights reserved.

*/

#pragma once

// GHASH for AES-256-GCM using Intel PCLMULQDQ.
//
// GHASH is multiplication in GF(2¹²⁸) with the irreducible polynomial
// x¹²⁸ + x⁷ + x² + x + 1 (the GCM polynomial), followed by XOR-accumulation.
//
// GCM bit ordering: GCM uses a "reflected" bit order where the most-significant
// bit of each byte is the coefficient of the lowest-power term.  We reflect
// inputs/outputs via a byte-reverse shuffle so that PCLMULQDQ operates in
// the natural (non-reflected) polynomial order.
//
// 128-bit polynomial multiply using PCLMULQDQ:
//   _mm_clmulepi64_si128(a, b, 0x00) = low(a) * low(b)    (64×64 → 128)
//   _mm_clmulepi64_si128(a, b, 0x11) = high(a) * high(b)  (64×64 → 128)
//   _mm_clmulepi64_si128(a, b, 0x10) = low(a) * high(b)
//   _mm_clmulepi64_si128(a, b, 0x01) = high(a) * low(b)
//
// Reduction modulo x¹²⁸ + x⁷ + x² + x + 1:
//   r(z) = 0x87 represented in the high-degree half.

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <immintrin.h>

#include "defs.hpp"


namespace ia_asm::detail {

// Load a 128-bit big-endian block and byte-reverse it for reflected GF arithmetic.
[[gnu::target("pclmul,ssse3")]]
static inline __m128i ghash_load_reflect(const uint8_t* block) noexcept {
    // Byte-swap shuffle: reverses the 16 bytes.
    const __m128i bswap = _mm_set_epi8( // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
    );
    return _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(block)), bswap);
}

[[gnu::target("pclmul,ssse3")]]
static inline void ghash_store_reflect(uint8_t* out, __m128i v) noexcept {
    const __m128i bswap = _mm_set_epi8( // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
    );
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out), _mm_shuffle_epi8(v, bswap));
}


// 128-bit carry-less multiply a * b → 256-bit result (lo, mid, hi).
[[gnu::target("pclmul,ssse3")]]
static inline void ghash_clmul256(__m128i a, __m128i b,
                                   __m128i& lo, __m128i& hi) noexcept {
    const __m128i lo_lo = _mm_clmulepi64_si128(a, b, 0x00); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers) lo(a)*lo(b)
    const __m128i hi_hi = _mm_clmulepi64_si128(a, b, 0x11); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers) hi(a)*hi(b)
    const __m128i lo_hi = _mm_clmulepi64_si128(a, b, 0x10); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers) lo(a)*hi(b)
    const __m128i hi_lo = _mm_clmulepi64_si128(a, b, 0x01); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers) hi(a)*lo(b)
    const __m128i mid   = _mm_xor_si128(lo_hi, hi_lo);

    // Combine mid terms: shift left 64 bits into lo, shift right 64 bits into hi.
    lo = _mm_xor_si128(lo_lo, _mm_slli_si128(mid, 8));   // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    hi = _mm_xor_si128(hi_hi, _mm_srli_si128(mid, 8));   // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
}


// Reduce a 256-bit poly value (lo, hi) modulo the GCM polynomial.
// Uses the Montgomery reduction with r(z) = 0x87 = x⁷ + x² + x + 1.
[[gnu::target("pclmul,ssse3")]]
static inline __m128i ghash_reduce(__m128i lo, __m128i hi) noexcept {
    // r(z) = 0xE1 in reflected bit order (= 0x87 reversed); must be in high 64-bit lane
    // so that clmulepi64_si128(..., 0x01) selects it as poly[127:64].
    const __m128i poly = _mm_set_epi64x(static_cast<long long>(0xE100000000000000ULL), 0); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)

    // First reduction step: reduce lower 64 bits of hi using r(z).
    __m128i tmp1 = _mm_clmulepi64_si128(hi, poly, 0x01); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers) hi0 * r
    tmp1 = _mm_xor_si128(tmp1, _mm_shuffle_epi32(hi, 0x4E)); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers) swap 64-bit halves
    hi = _mm_xor_si128(tmp1, lo);

    // Second reduction step on the adjusted result.
    __m128i tmp2 = _mm_clmulepi64_si128(hi, poly, 0x01); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    tmp2 = _mm_xor_si128(tmp2, _mm_shuffle_epi32(hi, 0x4E)); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    return _mm_xor_si128(tmp2, hi);
}


// GHASH context — acc and H are maintained in the reflected bit domain.
struct GhashCtx {
    __m128i acc; // NOLINT(misc-non-private-member-variables-in-classes)
    __m128i H;   // NOLINT(misc-non-private-member-variables-in-classes)

    [[gnu::target("pclmul,ssse3")]]
    void init(const uint8_t* H_block) noexcept {
        acc = _mm_setzero_si128();
        H   = ghash_load_reflect(H_block);
    }

    [[gnu::target("pclmul,ssse3")]]
    void update(const uint8_t* block) noexcept {
        const __m128i b = ghash_load_reflect(block);
        const __m128i x = _mm_xor_si128(acc, b);
        __m128i lo{};
        __m128i hi{};
        ghash_clmul256(x, H, lo, hi);
        acc = ghash_reduce(lo, hi);
    }

    [[gnu::target("pclmul,ssse3")]]
    void update_partial(const uint8_t* data, std::size_t len) noexcept {
        std::array<uint8_t, 16> buf{};
        std::memcpy(buf.data(), data, len);
        update(buf.data());
    }

    [[gnu::target("pclmul,ssse3")]]
    void finish(uint8_t* out) const noexcept {
        ghash_store_reflect(out, acc);
    }
};

}  // namespace ia_asm::detail
