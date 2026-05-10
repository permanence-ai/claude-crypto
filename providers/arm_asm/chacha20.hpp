// SPDX-License-Identifier: Apache-2.0

#pragma once

// ChaCha20 stream cipher (RFC 8439) using ARMv8 NEON SIMD.
//
// State layout — 4×4 matrix of 32-bit words:
//   [0]  = 0x61707865  [1]  = 0x3320646e  [2]  = 0x79622d32  [3]  = 0x6b206574
//   [4]  = key[0]      [5]  = key[1]      [6]  = key[2]      [7]  = key[3]
//   [8]  = key[4]      [9]  = key[5]      [10] = key[6]      [11] = key[7]
//   [12] = counter     [13] = nonce[0]    [14] = nonce[1]    [15] = nonce[2]
//
// Quarter-round QUARTERROUND(a,b,c,d):
//   a+=b; d^=a; d=ROT(d,16);
//   c+=d; b^=c; b=ROT(b,12);
//   a+=b; d^=a; d=ROT(d, 8);
//   c+=d; b^=c; b=ROT(b, 7);
//
// Single-block NEON (chacha20_block):
//   Row-major layout — 4 uint32x4_t, one per state row.  Column rounds work
//   on the registers directly; diagonal rounds rotate word positions with
//   vextq_u32 before and after.
//
// Four-block NEON (chacha20_xor4):
//   Word-major layout — 16 uint32x4_t where s[i] holds word i of all 4 blocks
//   in its lanes.  Blocks differ only in the counter (word 12).  In this layout
//   both column and diagonal QRs are plain chacha20_qr calls with different
//   register pairs — no vextq is needed.  The four QRs within each round type
//   are independent, allowing the out-of-order pipeline to issue them in
//   parallel.  After 10 double-rounds the state is transposed back to
//   block-major order and XOR'd with the input 16 bytes at a time.

#include <arm_neon.h>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>

#include "defs.hpp"
#include "secure_buffer.hpp"


namespace arm_asm::detail {

// ChaCha20 constant "expand 32-byte k" as four little-endian 32-bit words.
static constexpr uint32_t chacha20_c0 = 0x61707865U;
static constexpr uint32_t chacha20_c1 = 0x3320646eU;
static constexpr uint32_t chacha20_c2 = 0x79622d32U;
static constexpr uint32_t chacha20_c3 = 0x6b206574U;

// Rotate left 32-bit value by n bits using NEON vsriq/vshlq.
// For n in {7,8,12,16}: compiler uses vsriq_n_u32 + vshlq_n_u32.
template<int N>
[[nodiscard]]
[[gnu::target("neon")]]
static inline uint32x4_t rot32(uint32x4_t v) noexcept {
    return vorrq_u32(vshlq_n_u32(v, N), vshrq_n_u32(v, 32 - N));
}

// One ChaCha20 quarter-round on four NEON lanes simultaneously.
// Works for both row-major (single-block) and word-major (four-block) layouts;
// the arithmetic is identical — only the interpretation of the lanes differs.
[[gnu::target("neon")]]
static inline void chacha20_qr(uint32x4_t& a, uint32x4_t& b,
                                uint32x4_t& c, uint32x4_t& d) noexcept
{
    a = vaddq_u32(a, b); d = veorq_u32(d, a); d = rot32<16>(d);
    c = vaddq_u32(c, d); b = veorq_u32(b, c); b = rot32<12>(b);
    a = vaddq_u32(a, b); d = veorq_u32(d, a); d = rot32< 8>(d);
    c = vaddq_u32(c, d); b = veorq_u32(b, c); b = rot32< 7>(b);
}

// Load a 32-bit little-endian word from an unaligned pointer.
[[nodiscard]]
static inline uint32_t load_le32(const uint8_t* p) noexcept {
    uint32_t v{};
    std::memcpy(&v, p, 4);
    if constexpr (std::endian::native == std::endian::big) {
        v = std::byteswap(v);
    }
    return v;
}

// Store a 32-bit little-endian word to an unaligned pointer.
static inline void store_le32(uint8_t* p, uint32_t v) noexcept {
    if constexpr (std::endian::native == std::endian::big) {
        v = std::byteswap(v);
    }
    std::memcpy(p, &v, 4);
}

// Produce one 64-byte ChaCha20 keystream block into out[64].
// key: 32 bytes, counter: block counter (1-based for message), nonce: 12 bytes.
[[gnu::target("neon")]]
inline void chacha20_block(std::span<const uint8_t, 32> key, uint32_t counter,
                            std::span<const uint8_t, 12> nonce, std::span<uint8_t, 64> out) noexcept
{


    // Load key as 8 little-endian 32-bit words.
    const uint32_t k0  = load_le32(key.data() +  0);
    const uint32_t k1  = load_le32(key.data() +  4);
    const uint32_t k2  = load_le32(key.data() +  8);
    const uint32_t k3  = load_le32(key.data() + 12);
    const uint32_t k4  = load_le32(key.data() + 16);
    const uint32_t k5  = load_le32(key.data() + 20);
    const uint32_t k6  = load_le32(key.data() + 24);
    const uint32_t k7  = load_le32(key.data() + 28);
    const uint32_t n0  = load_le32(nonce.data() + 0);
    const uint32_t n1  = load_le32(nonce.data() + 4);
    const uint32_t n2  = load_le32(nonce.data() + 8);

    // Pack initial state into four NEON registers (row-major: each vector is a row).
    // row0 = [c0, c1, c2, c3]
    // row1 = [k0, k1, k2, k3]
    // row2 = [k4, k5, k6, k7]
    // row3 = [ctr, n0, n1, n2]
    uint32x4_t r0 = {chacha20_c0, chacha20_c1, chacha20_c2, chacha20_c3};
    uint32x4_t r1 = {k0, k1, k2, k3};
    uint32x4_t r2 = {k4, k5, k6, k7};
    uint32x4_t r3 = {counter, n0, n1, n2};

    const uint32x4_t orig0 = r0;
    const uint32x4_t orig1 = r1;
    const uint32x4_t orig2 = r2;
    const uint32x4_t orig3 = r3;

    // 20 rounds = 10 double-rounds.
    // Column rounds use indices (0,4,8,12),(1,5,9,13),(2,6,10,14),(3,7,11,15).
    // In row-major layout: column round = quarter-round on rows 0..3, lane i.
    // Diagonal rounds rotate the rows to align the diagonals:
    //   (0,5,10,15),(1,6,11,12),(2,7,8,13),(3,4,9,14)
    //   achieved by rotating r1 left by 1, r2 left by 2, r3 left by 3 (vextq_u32).
    for (int i = 0; i < 10; ++i) {
        // Column quarter-round.
        chacha20_qr(r0, r1, r2, r3);

        // Rotate rows to form diagonals.
        r1 = vextq_u32(r1, r1, 1);  // [1,2,3,0]
        r2 = vextq_u32(r2, r2, 2);  // [2,3,0,1]
        r3 = vextq_u32(r3, r3, 3);  // [3,0,1,2]

        // Diagonal quarter-round.
        chacha20_qr(r0, r1, r2, r3);

        // Rotate rows back.
        r1 = vextq_u32(r1, r1, 3);  // [3,0,1,2] → [0,1,2,3]
        r2 = vextq_u32(r2, r2, 2);  // [2,3,0,1] → [0,1,2,3]
        r3 = vextq_u32(r3, r3, 1);  // [1,2,3,0] → [0,1,2,3]
    }

    // Add original state (little-endian add, same as scalar).
    r0 = vaddq_u32(r0, orig0);
    r1 = vaddq_u32(r1, orig1);
    r2 = vaddq_u32(r2, orig2);
    r3 = vaddq_u32(r3, orig3);

    // Serialise as little-endian 32-bit words.
    // On little-endian hosts (Apple Silicon) vst1q_u32 is already correct.
    if constexpr (std::endian::native == std::endian::little) {
        vst1q_u32(reinterpret_cast<uint32_t*>(out.data() +  0), r0); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        vst1q_u32(reinterpret_cast<uint32_t*>(out.data() + 16), r1); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        vst1q_u32(reinterpret_cast<uint32_t*>(out.data() + 32), r2); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        vst1q_u32(reinterpret_cast<uint32_t*>(out.data() + 48), r3); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
    } else {
        // Big-endian: byte-swap each word.
        std::array<uint32_t, 4> tmp{};
        vst1q_u32(tmp.data(), r0);
        for (int j = 0; j < 4; ++j) { store_le32(out.data() + (static_cast<std::size_t>(j) * 4U), tmp[j]); }
        vst1q_u32(tmp.data(), r1);
        for (int j = 0; j < 4; ++j) { store_le32(out.data() + 16U + (static_cast<std::size_t>(j) * 4U), tmp[j]); }
        vst1q_u32(tmp.data(), r2);
        for (int j = 0; j < 4; ++j) { store_le32(out.data() + 32U + (static_cast<std::size_t>(j) * 4U), tmp[j]); }
        vst1q_u32(tmp.data(), r3);
        for (int j = 0; j < 4; ++j) { store_le32(out.data() + 48U + (static_cast<std::size_t>(j) * 4U), tmp[j]); }
    }
}


// ---------------------------------------------------------------------------
// Four-block parallel helpers
// ---------------------------------------------------------------------------

// Transpose a 4×4 matrix of uint32x4_t from column-major to row-major.
//
// Input:  a[i][j] = word i of block j  (each vector is one word across 4 blocks)
// Output: b[j] = words of block j packed consecutively  (each vector is one block's slice)
//
// Used to convert the word-major state produced by the 4-block round loop back
// into the block-major layout needed for the XOR step.
[[gnu::target("neon")]]
static inline void chacha20_transpose4( // NOLINT(readability-function-size,readability-function-cognitive-complexity)
    uint32x4_t a0, uint32x4_t a1, uint32x4_t a2, uint32x4_t a3,
    uint32x4_t& b0, uint32x4_t& b1, uint32x4_t& b2, uint32x4_t& b3) noexcept
{
    // vzipq_u32(a0,a1):
    //   val[0] = {a0[0],a1[0], a0[1],a1[1]}
    //   val[1] = {a0[2],a1[2], a0[3],a1[3]}
    const auto z01 = vzipq_u32(a0, a1);
    const auto z23 = vzipq_u32(a2, a3);
    // vzip1q_u64 / vzip2q_u64 select the low / high 64-bit halves.
    b0 = vreinterpretq_u32_u64(vzip1q_u64(vreinterpretq_u64_u32(z01.val[0]),
                                           vreinterpretq_u64_u32(z23.val[0])));
    b1 = vreinterpretq_u32_u64(vzip2q_u64(vreinterpretq_u64_u32(z01.val[0]),
                                           vreinterpretq_u64_u32(z23.val[0])));
    b2 = vreinterpretq_u32_u64(vzip1q_u64(vreinterpretq_u64_u32(z01.val[1]),
                                           vreinterpretq_u64_u32(z23.val[1])));
    b3 = vreinterpretq_u32_u64(vzip2q_u64(vreinterpretq_u64_u32(z01.val[1]),
                                           vreinterpretq_u64_u32(z23.val[1])));
}


// XOR 256 bytes (4 consecutive ChaCha20 blocks) of in[] into out[].
//
// Word-major layout: s[i] holds word i for all four blocks in its four lanes.
// In this layout both column and diagonal QRs are direct chacha20_qr calls —
// no vextq rotation is needed, and all four QRs within each round type operate
// on disjoint registers so the OoO pipeline can issue them simultaneously.
//
// Initial-state add-back is computed from the scalar key/counter/nonce values
// already in registers, saving 16 NEON registers vs. an explicit save.
[[gnu::target("neon")]]
static inline void chacha20_xor4( // NOLINT(readability-function-size,readability-function-cognitive-complexity)
    std::span<const uint8_t, 32> key, uint32_t counter,
    std::span<const uint8_t, 12> nonce,
    const uint8_t* in, uint8_t* out) noexcept
{
    const uint32_t k0 = load_le32(key.data() +  0);
    const uint32_t k1 = load_le32(key.data() +  4);
    const uint32_t k2 = load_le32(key.data() +  8);
    const uint32_t k3 = load_le32(key.data() + 12);
    const uint32_t k4 = load_le32(key.data() + 16);
    const uint32_t k5 = load_le32(key.data() + 20);
    const uint32_t k6 = load_le32(key.data() + 24);
    const uint32_t k7 = load_le32(key.data() + 28);
    const uint32_t n0 = load_le32(nonce.data() + 0);
    const uint32_t n1 = load_le32(nonce.data() + 4);
    const uint32_t n2 = load_le32(nonce.data() + 8);

    // Word-major state: s[i][lane] = word i of block `lane`.
    // Blocks 0..3 share the same key/nonce and differ only in the counter word.
    uint32x4_t s0  = vdupq_n_u32(chacha20_c0);
    uint32x4_t s1  = vdupq_n_u32(chacha20_c1);
    uint32x4_t s2  = vdupq_n_u32(chacha20_c2);
    uint32x4_t s3  = vdupq_n_u32(chacha20_c3);
    uint32x4_t s4  = vdupq_n_u32(k0);
    uint32x4_t s5  = vdupq_n_u32(k1);
    uint32x4_t s6  = vdupq_n_u32(k2);
    uint32x4_t s7  = vdupq_n_u32(k3);
    uint32x4_t s8  = vdupq_n_u32(k4);
    uint32x4_t s9  = vdupq_n_u32(k5);
    uint32x4_t s10 = vdupq_n_u32(k6);
    uint32x4_t s11 = vdupq_n_u32(k7);
    uint32x4_t s12 = {counter, counter + 1U, counter + 2U, counter + 3U};
    uint32x4_t s13 = vdupq_n_u32(n0);
    uint32x4_t s14 = vdupq_n_u32(n1);
    uint32x4_t s15 = vdupq_n_u32(n2);

    // 10 double-rounds.
    // Column rounds: (0,4,8,12), (1,5,9,13), (2,6,10,14), (3,7,11,15).
    // Diagonal rounds: (0,5,10,15), (1,6,11,12), (2,7,8,13), (3,4,9,14).
    // All four QRs within each round type are independent — the OoO pipeline
    // can issue them simultaneously.
    for (int i = 0; i < 10; ++i) {
        chacha20_qr(s0, s4, s8,  s12);
        chacha20_qr(s1, s5, s9,  s13);
        chacha20_qr(s2, s6, s10, s14);
        chacha20_qr(s3, s7, s11, s15);
        chacha20_qr(s0, s5, s10, s15);
        chacha20_qr(s1, s6, s11, s12);
        chacha20_qr(s2, s7, s8,  s13);
        chacha20_qr(s3, s4, s9,  s14);
    }

    // Add initial state back.  Recompute from scalars (already in scalar registers)
    // rather than saving 16 NEON registers before the round loop.
    s0  = vaddq_u32(s0,  vdupq_n_u32(chacha20_c0));
    s1  = vaddq_u32(s1,  vdupq_n_u32(chacha20_c1));
    s2  = vaddq_u32(s2,  vdupq_n_u32(chacha20_c2));
    s3  = vaddq_u32(s3,  vdupq_n_u32(chacha20_c3));
    s4  = vaddq_u32(s4,  vdupq_n_u32(k0));
    s5  = vaddq_u32(s5,  vdupq_n_u32(k1));
    s6  = vaddq_u32(s6,  vdupq_n_u32(k2));
    s7  = vaddq_u32(s7,  vdupq_n_u32(k3));
    s8  = vaddq_u32(s8,  vdupq_n_u32(k4));
    s9  = vaddq_u32(s9,  vdupq_n_u32(k5));
    s10 = vaddq_u32(s10, vdupq_n_u32(k6));
    s11 = vaddq_u32(s11, vdupq_n_u32(k7));
    const uint32x4_t ctr_init = {counter, counter + 1U, counter + 2U, counter + 3U};
    s12 = vaddq_u32(s12, ctr_init);
    s13 = vaddq_u32(s13, vdupq_n_u32(n0));
    s14 = vaddq_u32(s14, vdupq_n_u32(n1));
    s15 = vaddq_u32(s15, vdupq_n_u32(n2));

    // Transpose word-major → block-major.
    // Each chacha20_transpose4 call converts 4 word-registers into 4 block-slices:
    //   g{X}0 = words {4X..4X+3} of block 0
    //   g{X}1 = words {4X..4X+3} of block 1
    //   etc.
    uint32x4_t g00{};
    uint32x4_t g01{};
    uint32x4_t g02{};
    uint32x4_t g03{};
    uint32x4_t g10{};
    uint32x4_t g11{};
    uint32x4_t g12{};
    uint32x4_t g13{};
    uint32x4_t g20{};
    uint32x4_t g21{};
    uint32x4_t g22{};
    uint32x4_t g23{};
    uint32x4_t g30{};
    uint32x4_t g31{};
    uint32x4_t g32{};
    uint32x4_t g33{};

    chacha20_transpose4(s0,  s1,  s2,  s3,  g00, g01, g02, g03);
    chacha20_transpose4(s4,  s5,  s6,  s7,  g10, g11, g12, g13);
    chacha20_transpose4(s8,  s9,  s10, s11, g20, g21, g22, g23);
    chacha20_transpose4(s12, s13, s14, s15, g30, g31, g32, g33);

    // XOR 4 blocks with input (each block = g{0..3}k concatenated).
    // Block 0 (bytes 0..63)
    vst1q_u8(out +   0, veorq_u8(vld1q_u8(in +   0), vreinterpretq_u8_u32(g00)));
    vst1q_u8(out +  16, veorq_u8(vld1q_u8(in +  16), vreinterpretq_u8_u32(g10)));
    vst1q_u8(out +  32, veorq_u8(vld1q_u8(in +  32), vreinterpretq_u8_u32(g20)));
    vst1q_u8(out +  48, veorq_u8(vld1q_u8(in +  48), vreinterpretq_u8_u32(g30)));
    // Block 1 (bytes 64..127)
    vst1q_u8(out +  64, veorq_u8(vld1q_u8(in +  64), vreinterpretq_u8_u32(g01)));
    vst1q_u8(out +  80, veorq_u8(vld1q_u8(in +  80), vreinterpretq_u8_u32(g11)));
    vst1q_u8(out +  96, veorq_u8(vld1q_u8(in +  96), vreinterpretq_u8_u32(g21)));
    vst1q_u8(out + 112, veorq_u8(vld1q_u8(in + 112), vreinterpretq_u8_u32(g31)));
    // Block 2 (bytes 128..191)
    vst1q_u8(out + 128, veorq_u8(vld1q_u8(in + 128), vreinterpretq_u8_u32(g02)));
    vst1q_u8(out + 144, veorq_u8(vld1q_u8(in + 144), vreinterpretq_u8_u32(g12)));
    vst1q_u8(out + 160, veorq_u8(vld1q_u8(in + 160), vreinterpretq_u8_u32(g22)));
    vst1q_u8(out + 176, veorq_u8(vld1q_u8(in + 176), vreinterpretq_u8_u32(g32)));
    // Block 3 (bytes 192..255)
    vst1q_u8(out + 192, veorq_u8(vld1q_u8(in + 192), vreinterpretq_u8_u32(g03)));
    vst1q_u8(out + 208, veorq_u8(vld1q_u8(in + 208), vreinterpretq_u8_u32(g13)));
    vst1q_u8(out + 224, veorq_u8(vld1q_u8(in + 224), vreinterpretq_u8_u32(g23)));
    vst1q_u8(out + 240, veorq_u8(vld1q_u8(in + 240), vreinterpretq_u8_u32(g33)));
}


// Encrypt or decrypt len bytes at in[] → out[] using ChaCha20.
// counter_start: 1 for message data; nonce is 12 bytes (RFC 8439 format).
[[gnu::target("neon")]]
inline void chacha20_crypt(std::span<const uint8_t, 32> key, uint32_t counter_start,
                            std::span<const uint8_t, 12> nonce,
                            const uint8_t* in, uint8_t* out, std::size_t len) noexcept
{
    FixedSecureBuffer<64> block;
    uint32_t counter = counter_start;
    std::size_t offset = 0;

    // 4-block parallel path: 256 bytes at a time.
    while (len - offset >= 256U) {
        chacha20_xor4(key, counter, nonce,
                      in + offset, out + offset);
        offset  += 256U;
        counter += 4U;
    }

    // Single-block tail (0..3 full blocks).
    while (len - offset >= 64U) {
        chacha20_block(key, counter, nonce, std::span<uint8_t, 64>{block.data(), 64});
        const uint8x16_t k0 = vld1q_u8(block.data() +  0);
        const uint8x16_t k1 = vld1q_u8(block.data() + 16);
        const uint8x16_t k2 = vld1q_u8(block.data() + 32);
        const uint8x16_t k3 = vld1q_u8(block.data() + 48);
        vst1q_u8(out + offset +  0, veorq_u8(vld1q_u8(in + offset +  0), k0));
        vst1q_u8(out + offset + 16, veorq_u8(vld1q_u8(in + offset + 16), k1));
        vst1q_u8(out + offset + 32, veorq_u8(vld1q_u8(in + offset + 32), k2));
        vst1q_u8(out + offset + 48, veorq_u8(vld1q_u8(in + offset + 48), k3));
        offset  += 64U;
        ++counter;
    }

    // Partial final block.
    if (offset < len) {
        chacha20_block(key, counter, nonce, std::span<uint8_t, 64>{block.data(), 64});
        for (std::size_t i = 0; offset + i < len; ++i) {

            out[offset + i] = static_cast<uint8_t>(in[offset + i] ^ block[i]);
        }
    }
}

// Generate the 32-byte Poly1305 one-time key: first 32 bytes of ChaCha20
// block with counter=0 (RFC 8439 §2.6).
[[gnu::target("neon")]]
inline void chacha20_poly1305_key(std::span<const uint8_t, 32> key,
                                   std::span<const uint8_t, 12> nonce,
                                   std::span<uint8_t, 32> otk) noexcept
{
    FixedSecureBuffer<64> block;
    chacha20_block(key, 0, nonce, std::span<uint8_t, 64>{block.data(), 64});
    std::memcpy(otk.data(), block.data(), 32);
}

}  // namespace arm_asm::detail
