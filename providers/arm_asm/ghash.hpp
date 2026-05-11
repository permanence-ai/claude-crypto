// SPDX-License-Identifier: Apache-2.0

#pragma once

// GHASH for AES-256-GCM using ARMv8 PMULL crypto extensions.
//
// GHASH is multiplication in GF(2¹²⁸) with the irreducible polynomial
// x¹²⁸ + x⁷ + x² + x + 1 (the GCM polynomial), followed by XOR-accumulation.
//
// GCM bit ordering: GCM uses a "reflected" bit order where the most-significant
// bit of each byte is the coefficient of the lowest-power term.  The standard
// approach on ARM is to bit-reverse all inputs and outputs with vrbitq_u8 so
// that PMULL operates on the polynomial in its natural order.
//
// 128-bit polynomial multiply using four 64-bit PMULL:
//   Given a = a1:a0 and b = b1:b0 (each 64 bits):
//     h = a1*b1  (high 128 bits of product)
//     l = a0*b0  (low  128 bits of product)
//     m = a1*b0 + a0*b1  (cross terms, 128 bits)
//   Full 256-bit product = h<<128 + m<<64 + l
//
// Reduction modulo x¹²⁸ + x⁷ + x² + x + 1:
//   Modulus r(z) = x⁷ + x² + x + 1 → represented as 0x87.
//   Reduce the high 128 bits h using r(z): multiply h by 0x87, XOR into l.
//   Repeat if still > 128 bits (one further reduction is always sufficient).
//   This follows the algorithm from "Implementing GCM on ARMv8" (Gopal et al.)
//   Section 4.3, as used by MbedTLS.
//
// H precomputation: H = AES_K(0¹²⁸), bit-reversed for the reflected domain.

#include <arm_neon.h>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "defs.hpp"


namespace arm_asm::detail {

// Bit-reflect all bytes in a 128-bit vector.
[[nodiscard]]
[[gnu::target("aes,neon")]]
static inline uint8x16_t ghash_reflect(uint8x16_t v) noexcept {
    return vrbitq_u8(v);
}

// 128-bit polynomial multiply: returns a 256-bit result packed as three
// 128-bit values (high, middle, low) following the MbedTLS layout.
[[nodiscard]]
[[gnu::target("aes,neon")]]
static inline uint8x16x3_t ghash_poly_mult_128(uint8x16_t a, uint8x16_t b) noexcept {
    const poly64x2_t pa = vreinterpretq_p64_u8(a);
    const poly64x2_t pb = vreinterpretq_p64_u8(b);

    const uint8x16_t h = vreinterpretq_u8_p128(vmull_high_p64(pa, pb));     // a1*b1
    const uint8x16_t l = vreinterpretq_u8_p128(vmull_p64(                   // a0*b0
        (poly64_t)vget_low_p64(pa), (poly64_t)vget_low_p64(pb)));           // NOLINT(google-readability-casting,cppcoreguidelines-pro-type-cstyle-cast,modernize-avoid-c-style-cast)
    const poly64x2_t bs = vreinterpretq_p64_u8(vextq_u8(b, b, 8));          // b0:b1
    const uint8x16_t d  = vreinterpretq_u8_p128(vmull_high_p64(pa, bs));    // a1*b0
    const uint8x16_t e  = vreinterpretq_u8_p128(vmull_p64(                  // a0*b1
        (poly64_t)vget_low_p64(pa), (poly64_t)vget_low_p64(bs)));           // NOLINT(google-readability-casting,cppcoreguidelines-pro-type-cstyle-cast,modernize-avoid-c-style-cast)
    const uint8x16_t m  = veorq_u8(d, e);                                   // cross terms

    return uint8x16x3_t{ h, m, l };
}

// Reduce a 256-bit GF(2¹²⁸) value (packed as three 128-bit vectors) modulo
// the GCM polynomial x¹²⁸ + x⁷ + x² + x + 1 (constant 0x87).
[[nodiscard]]
[[gnu::target("aes,neon")]]
static inline uint8x16_t ghash_poly_reduce(uint8x16x3_t input) noexcept {
    const uint8x16_t ZERO   = vdupq_n_u8(0);
    // MODULO = 0x87 in byte 0 of each 64-bit lane: vshrq_n_u64(0x87..., 56)
    const uint64x2_t rbase  = vreinterpretq_u64_u8(vdupq_n_u8(0x87));
    const uint8x16_t MODULO = vreinterpretq_u8_u64(vshrq_n_u64(rbase, 64U - 8U));

    const uint8x16_t h = input.val[0];
    const uint8x16_t m = input.val[1];
    const uint8x16_t l = input.val[2];

    // Reduce high word h using r(z) = 0x87.
    const poly64x2_t ph      = vreinterpretq_p64_u8(h);
    const poly64x2_t pmod    = vreinterpretq_p64_u8(MODULO);
    const uint8x16_t c = vreinterpretq_u8_p128(vmull_high_p64(ph, pmod));    // c = h1 * 0x87
    const uint8x16_t d = vreinterpretq_u8_p128(vmull_p64(                    // d = h0 * 0x87
        (poly64_t)vget_low_p64(ph), (poly64_t)vget_low_p64(pmod)));          // NOLINT(google-readability-casting,cppcoreguidelines-pro-type-cstyle-cast,modernize-avoid-c-style-cast)

    const uint8x16_t e = veorq_u8(c, m);                                      // e = c + m
    // Reduce e using r(z) again (for the second half).
    const poly64x2_t pe = vreinterpretq_p64_u8(e);
    const uint8x16_t f = vreinterpretq_u8_p128(vmull_high_p64(pe, pmod));     // f = e1 * 0x87
    const uint8x16_t g = vextq_u8(ZERO, e, 8);                                // g = e1:00

    const uint8x16_t n = veorq_u8(d, l);
    const uint8x16_t o = veorq_u8(n, f);
    return veorq_u8(o, g);
}

// GHASH context — acc and H are maintained in the reflected bit domain.
// Reflection is applied once on input (in update) and once on output (in finish).
struct GhashCtx {
    uint8x16_t acc;  // NOLINT(misc-non-private-member-variables-in-classes)
    uint8x16_t H;    // NOLINT(misc-non-private-member-variables-in-classes)

    // H_block is AES_K(0¹²⁸) — 16 raw bytes; we reflect once here.
    [[gnu::target("aes,neon")]]
    void init(const uint8_t* H_block) noexcept {
        acc = vdupq_n_u8(0);
        H   = ghash_reflect(vld1q_u8(H_block));
    }

    // Feed one 16-byte block into the GHASH accumulator.
    [[gnu::target("aes,neon")]]
    void update(const uint8_t* block) noexcept {
        const uint8x16_t b = ghash_reflect(vld1q_u8(block));
        const uint8x16_t x = veorq_u8(acc, b);
        acc = ghash_poly_reduce(ghash_poly_mult_128(x, H));
    }

    // Feed a partial block (padded with zeros to 16 bytes).
    [[gnu::target("aes,neon")]]
    void update_partial(const uint8_t* data, std::size_t len) noexcept {
        ByteArray<16> buf{};
        std::memcpy(buf.data(), data, len);
        update(buf.data());
    }

    // Retrieve the 16-byte GHASH output; un-reflect acc back to GCM byte order.
    [[gnu::target("aes,neon")]]
    void finish(uint8_t* out) const noexcept {
        vst1q_u8(out, ghash_reflect(acc));
    }
};

}  // namespace arm_asm::detail
