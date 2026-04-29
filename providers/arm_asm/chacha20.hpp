/*
Copyright Permanence AI, 2026. All rights reserved.

*/

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
// NEON vectorisation: each of the four column quarter-rounds can be performed
// simultaneously on four uint32x4_t registers (one per row).  The diagonal
// rounds are handled by rotating the word positions within each vector.
//
// Block function produces a 64-byte keystream block.
// Encryption/decryption XOR the keystream with plaintext (same operation).
// Counter starts at 1 for message data (counter 0 is reserved for Poly1305
// one-time key generation per RFC 8439 §2.6).

#include <arm_neon.h>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "defs.hpp"


namespace arm_asm::detail {

// ChaCha20 constant "expand 32-byte k" as four little-endian 32-bit words.
static constexpr uint32_t chacha20_c0 = 0x61707865U;
static constexpr uint32_t chacha20_c1 = 0x3320646eU;
static constexpr uint32_t chacha20_c2 = 0x79622d32U;
static constexpr uint32_t chacha20_c3 = 0x6b206574U;

// Rotate left 32-bit value by n bits using NEON vsriq/vshlq.
// For n in {7,8,12,16}: compiler uses vsriq_n_u32 + vshlq_n_u32.
template<int N>
[[gnu::target("neon")]]
static inline uint32x4_t rot32(uint32x4_t v) noexcept {
    return vorrq_u32(vshlq_n_u32(v, N), vshrq_n_u32(v, 32 - N));
}

// One ChaCha20 quarter-round on four NEON lanes simultaneously.
// Operates on the columns (0,4,8,12), (1,5,9,13), (2,6,10,14), (3,7,11,15)
// packed as row vectors a[row0..3], b[row0..3], c[row0..3], d[row0..3].
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
static inline uint32_t load_le32(const uint8_t* p) noexcept {
    uint32_t v;
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
inline void chacha20_block(const uint8_t key[32], uint32_t counter,
                            const uint8_t nonce[12], uint8_t out[64]) noexcept
{
    // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)

    // Load key as 8 little-endian 32-bit words.
    const uint32_t k0  = load_le32(key +  0); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    const uint32_t k1  = load_le32(key +  4); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    const uint32_t k2  = load_le32(key +  8); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    const uint32_t k3  = load_le32(key + 12); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    const uint32_t k4  = load_le32(key + 16); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    const uint32_t k5  = load_le32(key + 20); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    const uint32_t k6  = load_le32(key + 24); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    const uint32_t k7  = load_le32(key + 28); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    const uint32_t n0  = load_le32(nonce + 0); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    const uint32_t n1  = load_le32(nonce + 4); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    const uint32_t n2  = load_le32(nonce + 8); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)

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
        vst1q_u32(reinterpret_cast<uint32_t*>(out +  0), r0); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic,cppcoreguidelines-pro-type-reinterpret-cast)
        vst1q_u32(reinterpret_cast<uint32_t*>(out + 16), r1); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic,cppcoreguidelines-pro-type-reinterpret-cast)
        vst1q_u32(reinterpret_cast<uint32_t*>(out + 32), r2); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic,cppcoreguidelines-pro-type-reinterpret-cast)
        vst1q_u32(reinterpret_cast<uint32_t*>(out + 48), r3); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic,cppcoreguidelines-pro-type-reinterpret-cast)
    } else {
        // Big-endian: byte-swap each word.
        uint32_t tmp[4];
        vst1q_u32(tmp, r0);
        for (int j = 0; j < 4; ++j) { store_le32(out + j * 4, tmp[j]); } // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        vst1q_u32(tmp, r1);
        for (int j = 0; j < 4; ++j) { store_le32(out + 16 + j * 4, tmp[j]); } // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic,cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        vst1q_u32(tmp, r2);
        for (int j = 0; j < 4; ++j) { store_le32(out + 32 + j * 4, tmp[j]); } // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic,cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        vst1q_u32(tmp, r3);
        for (int j = 0; j < 4; ++j) { store_le32(out + 48 + j * 4, tmp[j]); } // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic,cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    }
}

// Encrypt or decrypt len bytes at in[] → out[] using ChaCha20.
// counter_start: 1 for message data; nonce is 12 bytes (RFC 8439 format).
[[gnu::target("neon")]]
inline void chacha20_crypt(const uint8_t key[32], uint32_t counter_start,
                            const uint8_t nonce[12],
                            const uint8_t* in, uint8_t* out, std::size_t len) noexcept
{
    // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    uint8_t block[64]; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    uint32_t counter = counter_start;
    std::size_t offset = 0;

    while (len - offset >= 64) {
        chacha20_block(key, counter, nonce, block); // NOLINT(cppcoreguidelines-pro-bounds-array-to-pointer-decay,hicpp-no-array-decay)
        const uint8x16_t k0 = vld1q_u8(block +  0); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        const uint8x16_t k1 = vld1q_u8(block + 16); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        const uint8x16_t k2 = vld1q_u8(block + 32); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        const uint8x16_t k3 = vld1q_u8(block + 48); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        vst1q_u8(out + offset +  0, veorq_u8(vld1q_u8(in + offset +  0), k0)); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        vst1q_u8(out + offset + 16, veorq_u8(vld1q_u8(in + offset + 16), k1)); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        vst1q_u8(out + offset + 32, veorq_u8(vld1q_u8(in + offset + 32), k2)); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        vst1q_u8(out + offset + 48, veorq_u8(vld1q_u8(in + offset + 48), k3)); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        offset  += 64;
        ++counter;
    }

    if (offset < len) {
        chacha20_block(key, counter, nonce, block); // NOLINT(cppcoreguidelines-pro-bounds-array-to-pointer-decay,hicpp-no-array-decay)
        for (std::size_t i = 0; offset + i < len; ++i) {
            // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic,cppcoreguidelines-pro-bounds-constant-array-index)
            out[offset + i] = static_cast<uint8_t>(in[offset + i] ^ block[i]);
        }
    }

    // Zeroize block.
    volatile auto* p = reinterpret_cast<volatile uint8_t*>(block);
    for (std::size_t i = 0; i < 64; ++i) { p[i] = 0; } // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
}

// Generate the 32-byte Poly1305 one-time key: first 32 bytes of ChaCha20
// block with counter=0 (RFC 8439 §2.6).
[[gnu::target("neon")]]
inline void chacha20_poly1305_key(const uint8_t key[32], const uint8_t nonce[12],
                                   uint8_t otk[32]) noexcept
{
    // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    uint8_t block[64]; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    chacha20_block(key, 0, nonce, block); // NOLINT(cppcoreguidelines-pro-bounds-array-to-pointer-decay,hicpp-no-array-decay)
    std::memcpy(otk, block, 32);
    volatile auto* p = reinterpret_cast<volatile uint8_t*>(block);
    for (std::size_t i = 0; i < 64; ++i) { p[i] = 0; } // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
}

}  // namespace arm_asm::detail
