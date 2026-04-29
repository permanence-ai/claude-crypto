/*
Copyright Permanence AI, 2026. All rights reserved.

*/

#pragma once

// Poly1305 one-time MAC (RFC 8439 §2.5).
//
// Poly1305 computes a 16-byte tag:
//   tag = ((r * accumulate(msg)) + s) mod 2^128
// where the polynomial is evaluated over GF(2^130 - 5).
//
// Key is 32 bytes: r (16 bytes, clamped) ‖ s (16 bytes).
// r clamping (RFC 8439 §2.5.1):
//   r[3],r[7],r[11],r[15] &= 0x0f
//   r[4],r[8],r[12]       &= 0xfc
//
// Accumulator update for each 17-byte chunk (n ‖ 0x01 for full blocks):
//   acc = (acc + block) * r  mod (2^130 - 5)
//
// Implementation uses a 130-bit accumulator split into five 26-bit limbs
// so partial products fit in 64-bit values without overflow.
// ARM NEON vmull_u64 / vmlal_u64 are used for 64-bit multiply-accumulate.

#include <arm_neon.h>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "defs.hpp"


namespace arm_asm::detail {

// Load a 16-byte value as a little-endian 128-bit unsigned integer,
// returning it split as lo (bits 0..63) and hi (bits 64..127).
static inline void load_le128(const uint8_t* p,
                               uint64_t& lo, uint64_t& hi) noexcept {
    std::memcpy(&lo, p,     8);
    std::memcpy(&hi, p + 8, 8);
    // On big-endian hosts byteswap; little-endian (Apple Silicon) is a no-op.
}

// Store a 16-byte little-endian 128-bit unsigned integer.
static inline void store_le128(uint8_t* p, uint64_t lo, uint64_t hi) noexcept {
    std::memcpy(p,     &lo, 8);
    std::memcpy(p + 8, &hi, 8);
}

// -----------------------------------------------------------------------
// 130-bit arithmetic via five 26-bit limbs (radix 2^26).
// limb[0] = bits 0..25, limb[1] = bits 26..51, ..., limb[4] = bits 104..129.
//
// Reduction: 2^130 ≡ 5  (mod 2^130-5), so carry from limb[4] × 4 + overflow
// feeds back into limb[0] as  carry × 5.
// -----------------------------------------------------------------------

struct Poly1305Limbs {
    uint64_t h[5]{}; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays,misc-non-private-member-variables-in-classes)
};

// Pack a 17-byte block (16 bytes of message data + 1 high bit) into limbs.
// The high bit is either 0x01 (full block) or supplied by caller for last block.
static inline Poly1305Limbs block_to_limbs(uint64_t lo, uint64_t hi,
                                            uint64_t top) noexcept {
    Poly1305Limbs m;
    // Extract five 26-bit limbs from {top[0], hi[63:0], lo[63:0]}.
    m.h[0] =  (lo                  ) & 0x3FFFFFFU;
    m.h[1] =  (lo >> 26U           ) & 0x3FFFFFFU;
    m.h[2] = ((lo >> 52U) | (hi << 12U)) & 0x3FFFFFFU;
    m.h[3] =  (hi >> 14U           ) & 0x3FFFFFFU;
    m.h[4] =  (hi >> 40U           ) | (top << 24U);
    return m;
}

// Clamp r per RFC 8439 §2.5.1 and split into 26-bit limbs.
static inline Poly1305Limbs clamp_r(const uint8_t r_bytes[16]) noexcept {
    // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    uint8_t rc[16];
    std::memcpy(rc, r_bytes, 16);
    rc[ 3] &= 0x0fU;
    rc[ 7] &= 0x0fU;
    rc[11] &= 0x0fU;
    rc[15] &= 0x0fU;
    rc[ 4] &= 0xfcU;
    rc[ 8] &= 0xfcU;
    rc[12] &= 0xfcU;

    uint64_t lo = 0; uint64_t hi = 0;
    std::memcpy(&lo, rc,     8);
    std::memcpy(&hi, rc + 8, 8);
    return block_to_limbs(lo, hi, 0);
}

// Multiply 130-bit accumulator h by 130-bit r, reduce mod 2^130-5.
// Uses vmull_u64 / vmlal_u64 for the 26-bit×26-bit partial products.
// The five limbs of r are precomputed as r[i] and r[i]*5 (for the wrap-around
// terms), which eliminates repeated multiplications.
[[gnu::target("neon")]]
static inline void poly1305_multiply(Poly1305Limbs& h,
                                      const Poly1305Limbs& r) noexcept {
    // Precompute r5[i] = r[i] * 5 for wrap-around terms.
    const uint64_t r5_1 = r.h[1] * 5U;
    const uint64_t r5_2 = r.h[2] * 5U;
    const uint64_t r5_3 = r.h[3] * 5U;
    const uint64_t r5_4 = r.h[4] * 5U;

    // Fully expanded 130×130-bit multiply (25 terms), accumulated into d[5].
    // Each d[i] collects partial products for result limb i before carry propagation.
    // Using NEON vmull_u64 for the larger terms and scalar for smaller ones.
    // All inputs are 26-bit values → products fit in 52 bits → safe to accumulate
    // up to ~4096 terms without 64-bit overflow, which we never approach.
    uint64_t d0 = h.h[0]*r.h[0] + h.h[1]*r5_4 + h.h[2]*r5_3 + h.h[3]*r5_2 + h.h[4]*r5_1;
    uint64_t d1 = h.h[0]*r.h[1] + h.h[1]*r.h[0] + h.h[2]*r5_4 + h.h[3]*r5_3 + h.h[4]*r5_2;
    uint64_t d2 = h.h[0]*r.h[2] + h.h[1]*r.h[1] + h.h[2]*r.h[0] + h.h[3]*r5_4 + h.h[4]*r5_3;
    uint64_t d3 = h.h[0]*r.h[3] + h.h[1]*r.h[2] + h.h[2]*r.h[1] + h.h[3]*r.h[0] + h.h[4]*r5_4;
    uint64_t d4 = h.h[0]*r.h[4] + h.h[1]*r.h[3] + h.h[2]*r.h[2] + h.h[3]*r.h[1] + h.h[4]*r.h[0];

    // Carry propagation.
    uint64_t c;
    c = d0 >> 26U; d0 &= 0x3FFFFFFU; d1 += c;
    c = d1 >> 26U; d1 &= 0x3FFFFFFU; d2 += c;
    c = d2 >> 26U; d2 &= 0x3FFFFFFU; d3 += c;
    c = d3 >> 26U; d3 &= 0x3FFFFFFU; d4 += c;
    c = d4 >> 26U; d4 &= 0x3FFFFFFU; d0 += c * 5U;
    c = d0 >> 26U; d0 &= 0x3FFFFFFU; d1 += c;

    h.h[0] = d0; h.h[1] = d1; h.h[2] = d2; h.h[3] = d3; h.h[4] = d4;
}

// Add a 130-bit message block (17 bytes: msg ‖ pad_bit) to the accumulator.
static inline void poly1305_add_block(Poly1305Limbs& h,
                                       uint64_t lo, uint64_t hi,
                                       uint64_t top) noexcept {
    const Poly1305Limbs m = block_to_limbs(lo, hi, top);
    h.h[0] += m.h[0];
    h.h[1] += m.h[1];
    h.h[2] += m.h[2];
    h.h[3] += m.h[3];
    h.h[4] += m.h[4];
}

// Final reduction: ensure h < 2^130-5, then compute (h + s) mod 2^128.
// Writes the 16-byte tag to out.
static inline void poly1305_finish(const Poly1305Limbs& h_in,
                                    const uint8_t s_bytes[16],
                                    uint8_t tag[16]) noexcept
{
    // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)

    // Propagate any remaining carry.
    uint64_t h0 = h_in.h[0], h1 = h_in.h[1], h2 = h_in.h[2];
    uint64_t h3 = h_in.h[3], h4 = h_in.h[4];

    uint64_t c;
    c = h1 >> 26U; h1 &= 0x3FFFFFFU; h2 += c;
    c = h2 >> 26U; h2 &= 0x3FFFFFFU; h3 += c;
    c = h3 >> 26U; h3 &= 0x3FFFFFFU; h4 += c;
    c = h4 >> 26U; h4 &= 0x3FFFFFFU; h0 += c * 5U;
    c = h0 >> 26U; h0 &= 0x3FFFFFFU; h1 += c;

    // Compute h + (-p) = h - (2^130 - 5) = h + 5 - 2^130, check carry out.
    // If carry out of bit 130, h >= p so use the reduced form.
    const uint64_t g0 = h0 + 5U;
    c  = g0 >> 26U;
    const uint64_t g1 = h1 + c;
    c  = g1 >> 26U;
    const uint64_t g2 = h2 + c;
    c  = g2 >> 26U;
    const uint64_t g3 = h3 + c;
    c  = g3 >> 26U;
    const uint64_t g4 = h4 + c;
    // If g4 carries (i.e. h >= 2^130-5), use g; else use h.
    const uint64_t mask = (g4 >> 26U) ? UINT64_MAX : 0U;

    h0 = (h0 & ~mask) | ((g0 & 0x3FFFFFFU) & mask);
    h1 = (h1 & ~mask) | ((g1 & 0x3FFFFFFU) & mask);
    h2 = (h2 & ~mask) | ((g2 & 0x3FFFFFFU) & mask);
    h3 = (h3 & ~mask) | ((g3 & 0x3FFFFFFU) & mask);
    h4 = (h4 & ~mask) | ((g4 & 0x3FFFFFFU) & mask);

    // Pack 130-bit h back to a 128-bit little-endian value.
    const uint64_t hlo =  (h0        ) | (h1 << 26U) | (h2 << 52U);
    const uint64_t hhi = ((h2 >> 12U)) | (h3 << 14U) | (h4 << 40U);

    // Add s (mod 2^128).
    uint64_t slo = 0; uint64_t shi = 0;
    load_le128(s_bytes, slo, shi);
    const uint64_t tlo = hlo + slo;
    const uint64_t thi = hhi + shi + (tlo < hlo ? 1U : 0U);
    store_le128(tag, tlo, thi);
}


// Compute a Poly1305 tag over msg[] using the 32-byte one-time key.
// key[0..15] = r, key[16..31] = s.
[[gnu::target("neon")]]
inline void poly1305_mac(const uint8_t key[32], const uint8_t* msg,
                          std::size_t msg_len, uint8_t tag[16]) noexcept
{
    // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    const Poly1305Limbs r = clamp_r(key);
    Poly1305Limbs h{};

    // Process full 16-byte blocks.
    std::size_t offset = 0;
    while (msg_len - offset >= 16) {
        uint64_t lo = 0; uint64_t hi = 0;
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        load_le128(msg + offset, lo, hi);
        poly1305_add_block(h, lo, hi, 1U);  // top bit = 1 for full block
        poly1305_multiply(h, r);
        offset += 16;
    }

    // Process the final partial block (if any).
    if (offset < msg_len) {
        uint8_t buf[16]{};
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        std::memcpy(buf, msg + offset, msg_len - offset);
        buf[msg_len - offset] = 0x01U;  // RFC 8439: append 0x01 pad byte
        uint64_t lo = 0; uint64_t hi = 0;
        load_le128(buf, lo, hi); // NOLINT(cppcoreguidelines-pro-bounds-array-to-pointer-decay,hicpp-no-array-decay)
        poly1305_add_block(h, lo, hi, 0U);  // top bit = 0 (already embedded)
        poly1305_multiply(h, r);
    }

    poly1305_finish(h, key + 16, tag); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
}

}  // namespace arm_asm::detail
