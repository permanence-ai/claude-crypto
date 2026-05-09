// SPDX-License-Identifier: Apache-2.0

#pragma once

// ChaCha20 stream cipher (RFC 8439) using SSE2 SIMD.
//
// State layout — 4×4 matrix of 32-bit words:
//   [0]  = 0x61707865  [1]  = 0x3320646e  [2]  = 0x79622d32  [3]  = 0x6b206574
//   [4]  = key[0]      [5]  = key[1]      [6]  = key[2]      [7]  = key[3]
//   [8]  = key[4]      [9]  = key[5]      [10] = key[6]      [11] = key[7]
//   [12] = counter     [13] = nonce[0]    [14] = nonce[1]    [15] = nonce[2]
//
// Single-block SSE2 (chacha20_block):
//   Row-major layout — 4 __m128i, one per state row.  Column rounds work on the
//   registers directly; diagonal rounds use _mm_shuffle_epi32 to rotate lanes.
//
// Four-block SSE2 (chacha20_xor4):
//   Word-major layout — 16 __m128i where s[i] holds word i of all 4 blocks in
//   its lanes.  All four QRs in each round type are independent.

#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <emmintrin.h>  // SSE2
#include <tmmintrin.h>  // SSSE3 (_mm_shuffle_epi8, used for ROT8/ROT16)

#include "defs.hpp"
#include "secure_buffer.hpp"


namespace ia_asm::detail {

// ChaCha20 constant "expand 32-byte k" as four little-endian 32-bit words.
static constexpr uint32_t chacha20_c0 = 0x61707865U;
static constexpr uint32_t chacha20_c1 = 0x3320646eU;
static constexpr uint32_t chacha20_c2 = 0x79622d32U;
static constexpr uint32_t chacha20_c3 = 0x6b206574U;

// Load/store little-endian 32-bit word.
[[nodiscard]]
static inline uint32_t load_le32(const uint8_t* p) noexcept {
    uint32_t v{};
    std::memcpy(&v, p, 4);
    if constexpr (std::endian::native == std::endian::big) {
        v = std::byteswap(v);
    }
    return v;
}

static inline void store_le32(uint8_t* p, uint32_t v) noexcept {
    if constexpr (std::endian::native == std::endian::big) {
        v = std::byteswap(v);
    }
    std::memcpy(p, &v, 4);
}

// Rotate left 32-bit lanes by N bits using SSE2.
template<int N>
[[nodiscard]]
[[gnu::target("sse2")]]
static inline __m128i rot32(__m128i v) noexcept {
    static_assert(N > 0 && N < 32);
    return _mm_or_si128(_mm_slli_epi32(v, N), _mm_srli_epi32(v, 32 - N));
}

// One ChaCha20 quarter-round on four SSE2 lanes simultaneously.
[[gnu::target("sse2")]]
static inline void chacha20_qr(__m128i& a, __m128i& b,
                                __m128i& c, __m128i& d) noexcept
{
    a = _mm_add_epi32(a, b); d = _mm_xor_si128(d, a); d = rot32<16>(d);
    c = _mm_add_epi32(c, d); b = _mm_xor_si128(b, c); b = rot32<12>(b);
    a = _mm_add_epi32(a, b); d = _mm_xor_si128(d, a); d = rot32< 8>(d);
    c = _mm_add_epi32(c, d); b = _mm_xor_si128(b, c); b = rot32< 7>(b);
}

// Produce one 64-byte ChaCha20 keystream block into out[64].
[[gnu::target("sse2")]]
inline void chacha20_block(const uint8_t key[32], uint32_t counter,
                            const uint8_t nonce[12], uint8_t out[64]) noexcept
{
    const uint32_t k0 = load_le32(key +  0);
    const uint32_t k1 = load_le32(key +  4);
    const uint32_t k2 = load_le32(key +  8);
    const uint32_t k3 = load_le32(key + 12);
    const uint32_t k4 = load_le32(key + 16);
    const uint32_t k5 = load_le32(key + 20);
    const uint32_t k6 = load_le32(key + 24);
    const uint32_t k7 = load_le32(key + 28);
    const uint32_t n0 = load_le32(nonce + 0);
    const uint32_t n1 = load_le32(nonce + 4);
    const uint32_t n2 = load_le32(nonce + 8);

    // Row-major layout: each __m128i holds one row of the 4×4 state matrix.
    __m128i r0 = _mm_set_epi32(static_cast<int>(chacha20_c3), static_cast<int>(chacha20_c2),
                                static_cast<int>(chacha20_c1), static_cast<int>(chacha20_c0));
    __m128i r1 = _mm_set_epi32(static_cast<int>(k3), static_cast<int>(k2),
                                static_cast<int>(k1), static_cast<int>(k0));
    __m128i r2 = _mm_set_epi32(static_cast<int>(k7), static_cast<int>(k6),
                                static_cast<int>(k5), static_cast<int>(k4));
    __m128i r3 = _mm_set_epi32(static_cast<int>(n2), static_cast<int>(n1),
                                static_cast<int>(n0), static_cast<int>(counter));

    const __m128i orig0 = r0;
    const __m128i orig1 = r1;
    const __m128i orig2 = r2;
    const __m128i orig3 = r3;

    // 10 double-rounds: column QR, then rotate rows for diagonal QR, then rotate back.
    for (int i = 0; i < 10; ++i) {
        chacha20_qr(r0, r1, r2, r3);
        // Rotate rows to form diagonals: r1 left 1, r2 left 2, r3 left 3.
        r1 = _mm_shuffle_epi32(r1, 0x39); // [1,2,3,0]
        r2 = _mm_shuffle_epi32(r2, 0x4E); // [2,3,0,1]
        r3 = _mm_shuffle_epi32(r3, 0x93); // [3,0,1,2]
        chacha20_qr(r0, r1, r2, r3);
        // Rotate rows back.
        r1 = _mm_shuffle_epi32(r1, 0x93);
        r2 = _mm_shuffle_epi32(r2, 0x4E);
        r3 = _mm_shuffle_epi32(r3, 0x39);
    }

    r0 = _mm_add_epi32(r0, orig0);
    r1 = _mm_add_epi32(r1, orig1);
    r2 = _mm_add_epi32(r2, orig2);
    r3 = _mm_add_epi32(r3, orig3);

    // Store as little-endian 32-bit words (x86 is little-endian).
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out +  0), r0); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 16), r1); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 32), r2); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 48), r3); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
}


// XOR 256 bytes (4 consecutive ChaCha20 blocks) using word-major SSE2 layout.
[[gnu::target("sse2")]]
static inline void chacha20_xor4( // NOLINT(readability-function-size)
    const uint8_t key[32], uint32_t counter,
    const uint8_t nonce[12],
    const uint8_t* in, uint8_t* out) noexcept
{
    const uint32_t k0 = load_le32(key +  0);
    const uint32_t k1 = load_le32(key +  4);
    const uint32_t k2 = load_le32(key +  8);
    const uint32_t k3 = load_le32(key + 12);
    const uint32_t k4 = load_le32(key + 16);
    const uint32_t k5 = load_le32(key + 20);
    const uint32_t k6 = load_le32(key + 24);
    const uint32_t k7 = load_le32(key + 28);
    const uint32_t n0 = load_le32(nonce + 0);
    const uint32_t n1 = load_le32(nonce + 4);
    const uint32_t n2 = load_le32(nonce + 8);

    // Word-major: s[i][lane] = word i of block `lane`.
    __m128i s0  = _mm_set1_epi32(static_cast<int>(chacha20_c0));
    __m128i s1  = _mm_set1_epi32(static_cast<int>(chacha20_c1));
    __m128i s2  = _mm_set1_epi32(static_cast<int>(chacha20_c2));
    __m128i s3  = _mm_set1_epi32(static_cast<int>(chacha20_c3));
    __m128i s4  = _mm_set1_epi32(static_cast<int>(k0));
    __m128i s5  = _mm_set1_epi32(static_cast<int>(k1));
    __m128i s6  = _mm_set1_epi32(static_cast<int>(k2));
    __m128i s7  = _mm_set1_epi32(static_cast<int>(k3));
    __m128i s8  = _mm_set1_epi32(static_cast<int>(k4));
    __m128i s9  = _mm_set1_epi32(static_cast<int>(k5));
    __m128i s10 = _mm_set1_epi32(static_cast<int>(k6));
    __m128i s11 = _mm_set1_epi32(static_cast<int>(k7));
    __m128i s12 = _mm_set_epi32(static_cast<int>(counter + 3U), static_cast<int>(counter + 2U),
                                 static_cast<int>(counter + 1U), static_cast<int>(counter));
    __m128i s13 = _mm_set1_epi32(static_cast<int>(n0));
    __m128i s14 = _mm_set1_epi32(static_cast<int>(n1));
    __m128i s15 = _mm_set1_epi32(static_cast<int>(n2));

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

    s0  = _mm_add_epi32(s0,  _mm_set1_epi32(static_cast<int>(chacha20_c0)));
    s1  = _mm_add_epi32(s1,  _mm_set1_epi32(static_cast<int>(chacha20_c1)));
    s2  = _mm_add_epi32(s2,  _mm_set1_epi32(static_cast<int>(chacha20_c2)));
    s3  = _mm_add_epi32(s3,  _mm_set1_epi32(static_cast<int>(chacha20_c3)));
    s4  = _mm_add_epi32(s4,  _mm_set1_epi32(static_cast<int>(k0)));
    s5  = _mm_add_epi32(s5,  _mm_set1_epi32(static_cast<int>(k1)));
    s6  = _mm_add_epi32(s6,  _mm_set1_epi32(static_cast<int>(k2)));
    s7  = _mm_add_epi32(s7,  _mm_set1_epi32(static_cast<int>(k3)));
    s8  = _mm_add_epi32(s8,  _mm_set1_epi32(static_cast<int>(k4)));
    s9  = _mm_add_epi32(s9,  _mm_set1_epi32(static_cast<int>(k5)));
    s10 = _mm_add_epi32(s10, _mm_set1_epi32(static_cast<int>(k6)));
    s11 = _mm_add_epi32(s11, _mm_set1_epi32(static_cast<int>(k7)));
    s12 = _mm_add_epi32(s12, _mm_set_epi32(static_cast<int>(counter + 3U), static_cast<int>(counter + 2U),
                                             static_cast<int>(counter + 1U), static_cast<int>(counter)));
    s13 = _mm_add_epi32(s13, _mm_set1_epi32(static_cast<int>(n0)));
    s14 = _mm_add_epi32(s14, _mm_set1_epi32(static_cast<int>(n1)));
    s15 = _mm_add_epi32(s15, _mm_set1_epi32(static_cast<int>(n2)));

    // Transpose word-major → block-major and XOR with input.
    // For each block b (0..3): extract lane b from each s[i], pack into output.
    // We interleave (unpacklo/unpackhi) to transpose the 4×4 matrix.
    //
    // After transposing, 4 consecutive 16-byte chunks hold words 0..3 of block b.
    // We directly XOR with in[] and store to out[].
    //
    // Transpose pattern using SSE2 unpacks:
    //   t01_lo = unpacklo_epi32(s[i],  s[j]):  s[i][0], s[j][0], s[i][1], s[j][1]
    //   t01_hi = unpackhi_epi32(s[i],  s[j]):  s[i][2], s[j][2], s[i][3], s[j][3]
    //   t23_lo = unpacklo_epi32(s[k],  s[l]):  ...
    //   block0_words_ij = unpacklo_epi64(t01_lo, t23_lo):  s[i][0],s[j][0],s[k][0],s[l][0] → that's 4 words of block0 but from word-i,j,k,l positions
    // We process groups of 4 words at a time (rows 0..3, 4..7, 8..11, 12..15).

    auto xor_block_row = [&](std::size_t block_off, __m128i sa, __m128i sb, __m128i sc, __m128i sd) {
        const __m128i lo = _mm_unpacklo_epi32(sa, sb);  // b0w0 b1w0 b0w1 b1w1
        const __m128i hi = _mm_unpackhi_epi32(sa, sb);  // b2w0 b3w0 b2w1 b3w1
        const __m128i lo2 = _mm_unpacklo_epi32(sc, sd); // b0w2 b1w2 b0w3 b1w3
        const __m128i hi2 = _mm_unpackhi_epi32(sc, sd); // b2w2 b3w2 b2w3 b3w3

        const __m128i b0 = _mm_unpacklo_epi64(lo, lo2);  // b0: w0 w1 w2 w3
        const __m128i b1 = _mm_unpackhi_epi64(lo, lo2);  // b1: w0 w1 w2 w3
        const __m128i b2 = _mm_unpacklo_epi64(hi, hi2);  // b2: w0 w1 w2 w3
        const __m128i b3 = _mm_unpackhi_epi64(hi, hi2);  // b3: w0 w1 w2 w3

        _mm_storeu_si128(reinterpret_cast<__m128i*>(out + block_off +   0), _mm_xor_si128(b0, _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + block_off +   0)))); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        _mm_storeu_si128(reinterpret_cast<__m128i*>(out + block_off +  64), _mm_xor_si128(b1, _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + block_off +  64)))); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        _mm_storeu_si128(reinterpret_cast<__m128i*>(out + block_off + 128), _mm_xor_si128(b2, _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + block_off + 128)))); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        _mm_storeu_si128(reinterpret_cast<__m128i*>(out + block_off + 192), _mm_xor_si128(b3, _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + block_off + 192)))); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
    };

    xor_block_row( 0, s0, s1, s2, s3);   // words  0..3
    xor_block_row(16, s4, s5, s6, s7);   // words  4..7
    xor_block_row(32, s8, s9, s10, s11); // words  8..11
    xor_block_row(48, s12, s13, s14, s15); // words 12..15
}


// Encrypt or decrypt len bytes at in[] → out[] using ChaCha20.
// counter_start: 1 for message data; nonce is 12 bytes (RFC 8439 format).
[[gnu::target("sse2")]]
inline void chacha20_crypt(const uint8_t key[32], uint32_t counter_start,
                            const uint8_t nonce[12],
                            const uint8_t* in, uint8_t* out, std::size_t len) noexcept
{
    FixedSecureBuffer<64> block;
    uint32_t counter = counter_start;
    std::size_t offset = 0;

    while (len - offset >= 256U) {
        chacha20_xor4(key, counter, nonce,
                      in + offset, out + offset);
        offset  += 256U;
        counter += 4U;
    }

    while (len - offset >= 64U) {
        chacha20_block(key, counter, nonce, block.data());
        const __m128i k0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(block.data() +  0)); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        const __m128i k1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(block.data() + 16)); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        const __m128i k2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(block.data() + 32)); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        const __m128i k3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(block.data() + 48)); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        _mm_storeu_si128(reinterpret_cast<__m128i*>(out + offset +  0), _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(in + offset +  0)), k0)); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        _mm_storeu_si128(reinterpret_cast<__m128i*>(out + offset + 16), _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(in + offset + 16)), k1)); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        _mm_storeu_si128(reinterpret_cast<__m128i*>(out + offset + 32), _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(in + offset + 32)), k2)); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        _mm_storeu_si128(reinterpret_cast<__m128i*>(out + offset + 48), _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(in + offset + 48)), k3)); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        offset  += 64U;
        ++counter;
    }

    if (offset < len) {
        chacha20_block(key, counter, nonce, block.data());
        for (std::size_t i = 0; offset + i < len; ++i) {

            out[offset + i] = static_cast<uint8_t>(in[offset + i] ^ block[i]);
        }
    }
}

// Generate the 32-byte Poly1305 one-time key: first 32 bytes of ChaCha20
// block with counter=0 (RFC 8439 §2.6).
[[gnu::target("sse2")]]
inline void chacha20_poly1305_key(const uint8_t key[32], const uint8_t nonce[12],
                                   uint8_t otk[32]) noexcept
{
    FixedSecureBuffer<64> block;
    chacha20_block(key, 0, nonce, block.data());
    std::memcpy(otk, block.data(), 32);
}

}  // namespace ia_asm::detail
