// SPDX-License-Identifier: Apache-2.0

#pragma once

// SHA-256 using Intel SHA-NI extensions.
//
// Requires SHA-NI (Intel Goldmont+, AMD Zen+).  The -march=x86-64-v2+sha
// compile flag in the provider CMakeLists sets this.
//
// Intrinsics used:
//   _mm_sha256rnds2_epu32  — 2 SHA-256 rounds (message + state)
//   _mm_sha256msg1_epu32   — message schedule sigma0 step
//   _mm_sha256msg2_epu32   — message schedule sigma1 step
//   _mm_shuffle_epi8       — byte-swap for big-endian message load (SSSE3)
//   _mm_alignr_epi8        — extract 4-word shift for schedule (SSSE3)
//
// State layout: the SHA-NI intrinsics expect pairs of state words packed into
// 128-bit registers in a specific order:
//   abcd = { d, c, b, a }  (lane 0 = d = h3, lane 3 = a = h0)
//   efgh = { h, g, f, e }  (lane 0 = h = h7, lane 3 = e = h4)
//
// Constant-time by construction: no secret-dependent branches or memory
// accesses; all operations are hardware AES/SHA instructions.

#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <immintrin.h>

#include "defs.hpp"

#ifdef IA_ASM_SHA_NI_ENABLED
// defs.hpp (included above) already activates the full IA-ASM ISA pragma.
#endif // IA_ASM_SHA_NI_ENABLED


namespace ia_asm::detail {

// SHA-256 initial hash values (fractional parts of sqrt of first 8 primes).
inline constexpr uint32_t sha256_h0[8] = { // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
    0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U,
};

// SHA-256 round constants (fractional parts of cbrt of first 64 primes).
inline constexpr uint32_t sha256_k[64] = { // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
    0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
    0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
    0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
    0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
    0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
    0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U,
};


#ifdef IA_ASM_SHA_NI_ENABLED

// Process one 64-byte block using SHA-NI.
// state[0..7] = h0..h7 in standard SHA-256 order; updated in place.
// Message bytes are big-endian; load+byte-swap is done here.
// Constant-time by construction: no secret-dependent branches or memory accesses.
//
// Register layout follows the SHA-NI ABI:
//   state0 = { d, c, b, a }  (words 3..0)
//   state1 = { h, g, f, e }  (words 7..4)
// After each pair of _mm_sha256rnds2_epu32 calls the state rotates by 2.
// We save the initial state and add it back at the end (Davies–Meyer feed-forward).
//
// Message schedule:
//   msg0 = W[ 0.. 3], msg1 = W[ 4.. 7], msg2 = W[ 8..11], msg3 = W[12..15]
//   After the first 16 rounds, each group is updated in-place using
//   _mm_sha256msg1_epu32 (σ0) and _mm_sha256msg2_epu32 (σ1).
[[gnu::target("sha,ssse3,sse4.1"), gnu::noinline]]
void sha256_compress(uint32_t state[8], const uint8_t block[64]) noexcept // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays,readability-function-size)
{
    // Big-endian byte-swap mask: reverses 4-byte words within each 16-byte lane.
    const __m128i bswap_mask = _mm_set_epi8( // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        12, 13, 14, 15,  8,  9, 10, 11,  4,  5,  6,  7,  0,  1,  2,  3
    );

    // Load initial state.
    // SHA-NI expects { d, c, b, a } and { h, g, f, e }.
    __m128i state0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(state));     // a b c d
    __m128i state1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(state + 4)); // e f g h
    // Shuffle to { d c b a } and { h g f e }.
    state0 = _mm_shuffle_epi32(state0, 0xB1); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers) { b a d c }
    state1 = _mm_shuffle_epi32(state1, 0x1B); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers) { h g f e }
    __m128i tmp    = _mm_alignr_epi8(state0, state1, 8); // { d c b a } ← blend high of state1 low of state0
    state1         = _mm_blend_epi16(state1, state0, 0xF0); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    state0         = tmp;

    const __m128i init0 = state0;
    const __m128i init1 = state1;

    // Load 4 message words per register, byte-swap from big-endian.
    __m128i msg0 = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(block)),      bswap_mask);
    __m128i msg1 = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(block + 16)), bswap_mask); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers,cppcoreguidelines-pro-bounds-pointer-arithmetic)
    __m128i msg2 = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(block + 32)), bswap_mask); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers,cppcoreguidelines-pro-bounds-pointer-arithmetic)
    __m128i msg3 = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(block + 48)), bswap_mask); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers,cppcoreguidelines-pro-bounds-pointer-arithmetic)

    // Rounds 0–3
    __m128i tmp0 = _mm_add_epi32(msg0, _mm_loadu_si128(reinterpret_cast<const __m128i*>(sha256_k)));
    state1 = _mm_sha256rnds2_epu32(state1, state0, tmp0);
    state0 = _mm_sha256rnds2_epu32(state0, state1, _mm_shuffle_epi32(tmp0, 0x0E)); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    msg0 = _mm_sha256msg1_epu32(msg0, msg1);

    // Rounds 4–7
    __m128i tmp1 = _mm_add_epi32(msg1, _mm_loadu_si128(reinterpret_cast<const __m128i*>(sha256_k + 4))); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers,cppcoreguidelines-pro-bounds-pointer-arithmetic)
    state1 = _mm_sha256rnds2_epu32(state1, state0, tmp1);
    state0 = _mm_sha256rnds2_epu32(state0, state1, _mm_shuffle_epi32(tmp1, 0x0E)); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    msg1 = _mm_sha256msg1_epu32(msg1, msg2);

    // Rounds 8–11
    __m128i tmp2 = _mm_add_epi32(msg2, _mm_loadu_si128(reinterpret_cast<const __m128i*>(sha256_k + 8))); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers,cppcoreguidelines-pro-bounds-pointer-arithmetic)
    state1 = _mm_sha256rnds2_epu32(state1, state0, tmp2);
    state0 = _mm_sha256rnds2_epu32(state0, state1, _mm_shuffle_epi32(tmp2, 0x0E)); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    msg2 = _mm_sha256msg1_epu32(msg2, msg3);

    // Rounds 12–15
    __m128i tmp3 = _mm_add_epi32(msg3, _mm_loadu_si128(reinterpret_cast<const __m128i*>(sha256_k + 12))); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers,cppcoreguidelines-pro-bounds-pointer-arithmetic)
    state1 = _mm_sha256rnds2_epu32(state1, state0, tmp3);
    state0 = _mm_sha256rnds2_epu32(state0, state1, _mm_shuffle_epi32(tmp3, 0x0E)); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    msg3 = _mm_sha256msg1_epu32(msg3, msg0);

    // Rounds 16–19
    msg0 = _mm_sha256msg2_epu32(_mm_add_epi32(msg0, _mm_alignr_epi8(msg3, msg2, 4)), msg3); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    tmp0 = _mm_add_epi32(msg0, _mm_loadu_si128(reinterpret_cast<const __m128i*>(sha256_k + 16))); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers,cppcoreguidelines-pro-bounds-pointer-arithmetic)
    state1 = _mm_sha256rnds2_epu32(state1, state0, tmp0);
    state0 = _mm_sha256rnds2_epu32(state0, state1, _mm_shuffle_epi32(tmp0, 0x0E)); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    msg0 = _mm_sha256msg1_epu32(msg0, msg1);

    // Rounds 20–23
    msg1 = _mm_sha256msg2_epu32(_mm_add_epi32(msg1, _mm_alignr_epi8(msg0, msg3, 4)), msg0); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    tmp1 = _mm_add_epi32(msg1, _mm_loadu_si128(reinterpret_cast<const __m128i*>(sha256_k + 20))); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers,cppcoreguidelines-pro-bounds-pointer-arithmetic)
    state1 = _mm_sha256rnds2_epu32(state1, state0, tmp1);
    state0 = _mm_sha256rnds2_epu32(state0, state1, _mm_shuffle_epi32(tmp1, 0x0E)); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    msg1 = _mm_sha256msg1_epu32(msg1, msg2);

    // Rounds 24–27
    msg2 = _mm_sha256msg2_epu32(_mm_add_epi32(msg2, _mm_alignr_epi8(msg1, msg0, 4)), msg1); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    tmp2 = _mm_add_epi32(msg2, _mm_loadu_si128(reinterpret_cast<const __m128i*>(sha256_k + 24))); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers,cppcoreguidelines-pro-bounds-pointer-arithmetic)
    state1 = _mm_sha256rnds2_epu32(state1, state0, tmp2);
    state0 = _mm_sha256rnds2_epu32(state0, state1, _mm_shuffle_epi32(tmp2, 0x0E)); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    msg2 = _mm_sha256msg1_epu32(msg2, msg3);

    // Rounds 28–31
    msg3 = _mm_sha256msg2_epu32(_mm_add_epi32(msg3, _mm_alignr_epi8(msg2, msg1, 4)), msg2); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    tmp3 = _mm_add_epi32(msg3, _mm_loadu_si128(reinterpret_cast<const __m128i*>(sha256_k + 28))); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers,cppcoreguidelines-pro-bounds-pointer-arithmetic)
    state1 = _mm_sha256rnds2_epu32(state1, state0, tmp3);
    state0 = _mm_sha256rnds2_epu32(state0, state1, _mm_shuffle_epi32(tmp3, 0x0E)); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    msg3 = _mm_sha256msg1_epu32(msg3, msg0);

    // Rounds 32–35
    msg0 = _mm_sha256msg2_epu32(_mm_add_epi32(msg0, _mm_alignr_epi8(msg3, msg2, 4)), msg3); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    tmp0 = _mm_add_epi32(msg0, _mm_loadu_si128(reinterpret_cast<const __m128i*>(sha256_k + 32))); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers,cppcoreguidelines-pro-bounds-pointer-arithmetic)
    state1 = _mm_sha256rnds2_epu32(state1, state0, tmp0);
    state0 = _mm_sha256rnds2_epu32(state0, state1, _mm_shuffle_epi32(tmp0, 0x0E)); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    msg0 = _mm_sha256msg1_epu32(msg0, msg1);

    // Rounds 36–39
    msg1 = _mm_sha256msg2_epu32(_mm_add_epi32(msg1, _mm_alignr_epi8(msg0, msg3, 4)), msg0); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    tmp1 = _mm_add_epi32(msg1, _mm_loadu_si128(reinterpret_cast<const __m128i*>(sha256_k + 36))); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers,cppcoreguidelines-pro-bounds-pointer-arithmetic)
    state1 = _mm_sha256rnds2_epu32(state1, state0, tmp1);
    state0 = _mm_sha256rnds2_epu32(state0, state1, _mm_shuffle_epi32(tmp1, 0x0E)); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    msg1 = _mm_sha256msg1_epu32(msg1, msg2);

    // Rounds 40–43
    msg2 = _mm_sha256msg2_epu32(_mm_add_epi32(msg2, _mm_alignr_epi8(msg1, msg0, 4)), msg1); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    tmp2 = _mm_add_epi32(msg2, _mm_loadu_si128(reinterpret_cast<const __m128i*>(sha256_k + 40))); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers,cppcoreguidelines-pro-bounds-pointer-arithmetic)
    state1 = _mm_sha256rnds2_epu32(state1, state0, tmp2);
    state0 = _mm_sha256rnds2_epu32(state0, state1, _mm_shuffle_epi32(tmp2, 0x0E)); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    msg2 = _mm_sha256msg1_epu32(msg2, msg3);

    // Rounds 44–47
    msg3 = _mm_sha256msg2_epu32(_mm_add_epi32(msg3, _mm_alignr_epi8(msg2, msg1, 4)), msg2); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    tmp3 = _mm_add_epi32(msg3, _mm_loadu_si128(reinterpret_cast<const __m128i*>(sha256_k + 44))); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers,cppcoreguidelines-pro-bounds-pointer-arithmetic)
    state1 = _mm_sha256rnds2_epu32(state1, state0, tmp3);
    state0 = _mm_sha256rnds2_epu32(state0, state1, _mm_shuffle_epi32(tmp3, 0x0E)); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    msg3 = _mm_sha256msg1_epu32(msg3, msg0);

    // Rounds 48–51
    msg0 = _mm_sha256msg2_epu32(_mm_add_epi32(msg0, _mm_alignr_epi8(msg3, msg2, 4)), msg3); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    tmp0 = _mm_add_epi32(msg0, _mm_loadu_si128(reinterpret_cast<const __m128i*>(sha256_k + 48))); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers,cppcoreguidelines-pro-bounds-pointer-arithmetic)
    state1 = _mm_sha256rnds2_epu32(state1, state0, tmp0);
    state0 = _mm_sha256rnds2_epu32(state0, state1, _mm_shuffle_epi32(tmp0, 0x0E)); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)

    // Rounds 52–55
    msg1 = _mm_sha256msg2_epu32(_mm_add_epi32(msg1, _mm_alignr_epi8(msg0, msg3, 4)), msg0); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    tmp1 = _mm_add_epi32(msg1, _mm_loadu_si128(reinterpret_cast<const __m128i*>(sha256_k + 52))); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers,cppcoreguidelines-pro-bounds-pointer-arithmetic)
    state1 = _mm_sha256rnds2_epu32(state1, state0, tmp1);
    state0 = _mm_sha256rnds2_epu32(state0, state1, _mm_shuffle_epi32(tmp1, 0x0E)); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)

    // Rounds 56–59
    msg2 = _mm_sha256msg2_epu32(_mm_add_epi32(msg2, _mm_alignr_epi8(msg1, msg0, 4)), msg1); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    tmp2 = _mm_add_epi32(msg2, _mm_loadu_si128(reinterpret_cast<const __m128i*>(sha256_k + 56))); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers,cppcoreguidelines-pro-bounds-pointer-arithmetic)
    state1 = _mm_sha256rnds2_epu32(state1, state0, tmp2);
    state0 = _mm_sha256rnds2_epu32(state0, state1, _mm_shuffle_epi32(tmp2, 0x0E)); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)

    // Rounds 60–63
    msg3 = _mm_sha256msg2_epu32(_mm_add_epi32(msg3, _mm_alignr_epi8(msg2, msg1, 4)), msg2); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    tmp3 = _mm_add_epi32(msg3, _mm_loadu_si128(reinterpret_cast<const __m128i*>(sha256_k + 60))); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers,cppcoreguidelines-pro-bounds-pointer-arithmetic)
    state1 = _mm_sha256rnds2_epu32(state1, state0, tmp3);
    state0 = _mm_sha256rnds2_epu32(state0, state1, _mm_shuffle_epi32(tmp3, 0x0E)); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)

    // Davies–Meyer feed-forward: add back the initial state.
    state0 = _mm_add_epi32(state0, init0);
    state1 = _mm_add_epi32(state1, init1);

    // Convert back from SHA-NI ABEF/CDGH layout to h0..h7 word order.
    // Reference: noloader/SHA-Intrinsics sha256-x86.c
    tmp    = _mm_shuffle_epi32(state0, 0x1B); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers) FEBA
    state1 = _mm_shuffle_epi32(state1, 0xB1); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers) DCHG
    state0 = _mm_blend_epi16(tmp, state1, 0xF0); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers) DCBA
    state1 = _mm_alignr_epi8(state1, tmp, 8); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers) HGFE

    _mm_storeu_si128(reinterpret_cast<__m128i*>(state),     state0);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(state + 4), state1);
}

#else // IA_ASM_SHA_NI_ENABLED — portable scalar fallback

// Portable scalar SHA-256 compress. Used when SHA-NI is disabled.
inline void sha256_compress(uint32_t state[8], const uint8_t block[64]) noexcept // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays,readability-function-size)
{
    auto rotr = [](uint32_t x, int n) noexcept { return (x >> n) | (x << (32 - n)); }; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    auto ch   = [](uint32_t x, uint32_t y, uint32_t z) noexcept { return (x & y) ^ (~x & z); };
    auto maj  = [](uint32_t x, uint32_t y, uint32_t z) noexcept { return (x & y) ^ (x & z) ^ (y & z); };

    uint32_t w[64]; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays,cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    for (std::size_t i = 0; i < 16; ++i) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        w[i] = (static_cast<uint32_t>(block[i * 4])     << 24U) | // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers,cppcoreguidelines-pro-bounds-pointer-arithmetic)
               (static_cast<uint32_t>(block[i * 4 + 1]) << 16U) | // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers,cppcoreguidelines-pro-bounds-pointer-arithmetic)
               (static_cast<uint32_t>(block[i * 4 + 2]) <<  8U) | // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers,cppcoreguidelines-pro-bounds-pointer-arithmetic)
                static_cast<uint32_t>(block[i * 4 + 3]);           // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers,cppcoreguidelines-pro-bounds-pointer-arithmetic)
    }
    for (std::size_t i = 16; i < 64; ++i) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        const uint32_t s0 = rotr(w[i-15], 7) ^ rotr(w[i-15], 18) ^ (w[i-15] >> 3); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers,cppcoreguidelines-pro-bounds-pointer-arithmetic)
        const uint32_t s1 = rotr(w[i-2],  17) ^ rotr(w[i-2], 19) ^ (w[i-2]  >> 10); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers,cppcoreguidelines-pro-bounds-pointer-arithmetic)
        w[i] = (w[i-16] + s0 + w[i-7] + s1) & 0xFFFFFFFFU; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers,cppcoreguidelines-pro-bounds-pointer-arithmetic)
    }
    uint32_t a = state[0]; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    uint32_t b = state[1]; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    uint32_t c = state[2]; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    uint32_t d = state[3]; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    uint32_t e = state[4]; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    uint32_t f = state[5]; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    uint32_t g = state[6]; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    uint32_t h = state[7]; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    for (std::size_t i = 0; i < 64; ++i) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        const uint32_t s1  = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        const uint32_t t1  = (h + s1 + ch(e,f,g) + sha256_k[i] + w[i]) & 0xFFFFFFFFU; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        const uint32_t s0  = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        const uint32_t t2  = (s0 + maj(a,b,c)) & 0xFFFFFFFFU;
        h=g; g=f; f=e; e=(d+t1)&0xFFFFFFFFU; d=c; c=b; b=a; a=(t1+t2)&0xFFFFFFFFU;
    }
    state[0] = (state[0]+a)&0xFFFFFFFFU; state[1] = (state[1]+b)&0xFFFFFFFFU; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    state[2] = (state[2]+c)&0xFFFFFFFFU; state[3] = (state[3]+d)&0xFFFFFFFFU; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    state[4] = (state[4]+e)&0xFFFFFFFFU; state[5] = (state[5]+f)&0xFFFFFFFFU; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    state[6] = (state[6]+g)&0xFFFFFFFFU; state[7] = (state[7]+h)&0xFFFFFFFFU; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
}

#endif // IA_ASM_SHA_NI_ENABLED


// Full SHA-256 over an arbitrary-length message.
// Handles padding and big-endian length encoding.
inline void sha256(const CryptoByte* msg, std::size_t msg_len,
                   CryptoByte out[32]) noexcept // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
{
    uint32_t state[8]; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    for (std::size_t i = 0; i < 8; ++i) { state[i] = sha256_h0[i]; }

    // Process all complete 64-byte blocks.
    std::size_t offset = 0;
    while (msg_len - offset >= 64) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        sha256_compress(state, msg + offset); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        offset += 64; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    }

    // Build the final padded block(s).
    alignas(64) uint8_t pad[128]{}; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays,cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    const std::size_t tail = msg_len - offset;
    if (tail > 0) { std::memcpy(pad, msg + offset, tail); } // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    pad[tail] = 0x80U;

    // Append bit-length as big-endian uint64 in the last 8 bytes.
    const uint64_t bit_len_be = std::byteswap(static_cast<uint64_t>(msg_len) * 8U); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    if (tail < 56) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        std::memcpy(pad + 56, &bit_len_be, 8); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers,cppcoreguidelines-pro-bounds-pointer-arithmetic)
        sha256_compress(state, pad);
    } else {
        std::memcpy(pad + 120, &bit_len_be, 8); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers,cppcoreguidelines-pro-bounds-pointer-arithmetic)
        sha256_compress(state, pad);
        sha256_compress(state, pad + 64); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers,cppcoreguidelines-pro-bounds-pointer-arithmetic)
    }

    // Serialise state as big-endian bytes.
    for (std::size_t i = 0; i < 8; ++i) {
        const uint32_t w = std::byteswap(state[i]);
        std::memcpy(out + (i * 4), &w, 4); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers,cppcoreguidelines-pro-bounds-pointer-arithmetic)
    }
}

}  // namespace ia_asm::detail
