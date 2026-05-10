// SPDX-License-Identifier: Apache-2.0

#pragma once

// SHA-256 using ARMv8 SHA2 crypto extensions.
//
// Requires __ARM_FEATURE_SHA2 (Apple Silicon and any ARMv8-A+crypto core).
// The -march=armv8.2-a+crypto flag in the provider CMakeLists sets this.

#include <arm_neon.h>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>

#include "defs.hpp"


namespace arm_asm::detail {

// SHA-256 initial hash values (fractional parts of sqrt of first 8 primes).
inline constexpr std::array<uint32_t, 8> sha256_h0 = {
    0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
    0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U,
};

// SHA-256 round constants (fractional parts of cbrt of first 64 primes).
inline constexpr std::array<uint32_t, 64> sha256_k = {
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


// Process one 64-byte block.  state[0..7] = h0..h7, updated in place.
// Message bytes are big-endian; load+byteswap is done here.
// Constant-time by construction: no secret-dependent branches or memory accesses.
//
// Message schedule interleaving:
//   Each of the 16 groups of 4 rounds follows the pattern:
//     1. Compute tmp = wa + k  (captures current wa before schedule overwrites it)
//     2. su0(wa, wb)  → wa now holds the partial schedule for W[group+16]
//     3. vsha256h + vsha256h2 using tmp
//     4. su1(wa_prev, wc, wd)  → completes the schedule 1 group behind
//   Groups 12-15 (rounds 48-63) skip su0; group 12 completes the last su1.
[[gnu::target("sha2,neon")]]
inline void sha256_compress(std::span<uint32_t, 8> state, const uint8_t* block) noexcept // NOLINT(readability-function-size,readability-function-cognitive-complexity)
{
    uint32x4_t abcd = vld1q_u32(state.data());
    uint32x4_t efgh = vld1q_u32(state.data() + 4);
    const uint32x4_t abcd0 = abcd;
    const uint32x4_t efgh0 = efgh;

    // Load 16 message words, converting from big-endian bytes.
    uint32x4_t w0 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block)));
    uint32x4_t w1 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block + 16)));
    uint32x4_t w2 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block + 32)));
    uint32x4_t w3 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block + 48)));

    uint32x4_t tmp;
    uint32x4_t save;

    // Group 0 (rounds 0-3): hash W[0..3]; su0 → partial W[16..19] in w0.
    tmp = vaddq_u32(w0, vld1q_u32(sha256_k.data()));
    save = abcd;
    w0 = vsha256su0q_u32(w0, w1);
    abcd = vsha256hq_u32(abcd, efgh, tmp);
    efgh = vsha256h2q_u32(efgh, save, tmp);

    // Group 1 (rounds 4-7): hash W[4..7]; su0 → partial W[20..23] in w1;
    //                        su1 → complete W[16..19] in w0.
    tmp = vaddq_u32(w1, vld1q_u32(sha256_k.data() + 4));
    save = abcd;
    w1 = vsha256su0q_u32(w1, w2);
    abcd = vsha256hq_u32(abcd, efgh, tmp);
    efgh = vsha256h2q_u32(efgh, save, tmp);
    w0 = vsha256su1q_u32(w0, w2, w3);

    // Group 2 (rounds 8-11): hash W[8..11]; su0 → partial W[24..27];
    //                         su1 → complete W[20..23].
    tmp = vaddq_u32(w2, vld1q_u32(sha256_k.data() + 8));
    save = abcd;
    w2 = vsha256su0q_u32(w2, w3);
    abcd = vsha256hq_u32(abcd, efgh, tmp);
    efgh = vsha256h2q_u32(efgh, save, tmp);
    w1 = vsha256su1q_u32(w1, w3, w0);

    // Group 3 (rounds 12-15): hash W[12..15]; su0 → partial W[28..31];
    //                          su1 → complete W[24..27].
    tmp = vaddq_u32(w3, vld1q_u32(sha256_k.data() + 12));
    save = abcd;
    w3 = vsha256su0q_u32(w3, w0);
    abcd = vsha256hq_u32(abcd, efgh, tmp);
    efgh = vsha256h2q_u32(efgh, save, tmp);
    w2 = vsha256su1q_u32(w2, w0, w1);

    // Group 4 (rounds 16-19): hash W[16..19]; su0 → partial W[32..35];
    //                          su1 → complete W[28..31].
    tmp = vaddq_u32(w0, vld1q_u32(sha256_k.data() + 16));
    save = abcd;
    w0 = vsha256su0q_u32(w0, w1);
    abcd = vsha256hq_u32(abcd, efgh, tmp);
    efgh = vsha256h2q_u32(efgh, save, tmp);
    w3 = vsha256su1q_u32(w3, w1, w2);

    // Group 5 (rounds 20-23)
    tmp = vaddq_u32(w1, vld1q_u32(sha256_k.data() + 20));
    save = abcd;
    w1 = vsha256su0q_u32(w1, w2);
    abcd = vsha256hq_u32(abcd, efgh, tmp);
    efgh = vsha256h2q_u32(efgh, save, tmp);
    w0 = vsha256su1q_u32(w0, w2, w3);

    // Group 6 (rounds 24-27)
    tmp = vaddq_u32(w2, vld1q_u32(sha256_k.data() + 24));
    save = abcd;
    w2 = vsha256su0q_u32(w2, w3);
    abcd = vsha256hq_u32(abcd, efgh, tmp);
    efgh = vsha256h2q_u32(efgh, save, tmp);
    w1 = vsha256su1q_u32(w1, w3, w0);

    // Group 7 (rounds 28-31)
    tmp = vaddq_u32(w3, vld1q_u32(sha256_k.data() + 28));
    save = abcd;
    w3 = vsha256su0q_u32(w3, w0);
    abcd = vsha256hq_u32(abcd, efgh, tmp);
    efgh = vsha256h2q_u32(efgh, save, tmp);
    w2 = vsha256su1q_u32(w2, w0, w1);

    // Group 8 (rounds 32-35)
    tmp = vaddq_u32(w0, vld1q_u32(sha256_k.data() + 32));
    save = abcd;
    w0 = vsha256su0q_u32(w0, w1);
    abcd = vsha256hq_u32(abcd, efgh, tmp);
    efgh = vsha256h2q_u32(efgh, save, tmp);
    w3 = vsha256su1q_u32(w3, w1, w2);

    // Group 9 (rounds 36-39)
    tmp = vaddq_u32(w1, vld1q_u32(sha256_k.data() + 36));
    save = abcd;
    w1 = vsha256su0q_u32(w1, w2);
    abcd = vsha256hq_u32(abcd, efgh, tmp);
    efgh = vsha256h2q_u32(efgh, save, tmp);
    w0 = vsha256su1q_u32(w0, w2, w3);

    // Group 10 (rounds 40-43)
    tmp = vaddq_u32(w2, vld1q_u32(sha256_k.data() + 40));
    save = abcd;
    w2 = vsha256su0q_u32(w2, w3);
    abcd = vsha256hq_u32(abcd, efgh, tmp);
    efgh = vsha256h2q_u32(efgh, save, tmp);
    w1 = vsha256su1q_u32(w1, w3, w0);

    // Group 11 (rounds 44-47)
    tmp = vaddq_u32(w3, vld1q_u32(sha256_k.data() + 44));
    save = abcd;
    w3 = vsha256su0q_u32(w3, w0);
    abcd = vsha256hq_u32(abcd, efgh, tmp);
    efgh = vsha256h2q_u32(efgh, save, tmp);
    w2 = vsha256su1q_u32(w2, w0, w1);

    // Group 12 (rounds 48-51): no su0; su1 → complete W[60..63].
    tmp = vaddq_u32(w0, vld1q_u32(sha256_k.data() + 48));
    save = abcd;
    abcd = vsha256hq_u32(abcd, efgh, tmp);
    efgh = vsha256h2q_u32(efgh, save, tmp);
    w3 = vsha256su1q_u32(w3, w1, w2);

    // Group 13 (rounds 52-55): no schedule.
    tmp = vaddq_u32(w1, vld1q_u32(sha256_k.data() + 52));
    save = abcd;
    abcd = vsha256hq_u32(abcd, efgh, tmp);
    efgh = vsha256h2q_u32(efgh, save, tmp);

    // Group 14 (rounds 56-59)
    tmp = vaddq_u32(w2, vld1q_u32(sha256_k.data() + 56));
    save = abcd;
    abcd = vsha256hq_u32(abcd, efgh, tmp);
    efgh = vsha256h2q_u32(efgh, save, tmp);

    // Group 15 (rounds 60-63)
    tmp = vaddq_u32(w3, vld1q_u32(sha256_k.data() + 60));
    save = abcd;
    abcd = vsha256hq_u32(abcd, efgh, tmp);
    efgh = vsha256h2q_u32(efgh, save, tmp);

    vst1q_u32(state.data(),     vaddq_u32(abcd, abcd0));
    vst1q_u32(state.data() + 4, vaddq_u32(efgh, efgh0));
}


// Full SHA-256 over an arbitrary-length message.
// Handles padding and big-endian length encoding.
inline void sha256(const CryptoByte* msg, std::size_t msg_len,
                   std::span<CryptoByte, 32> out) noexcept
{
    std::array<uint32_t, 8> state{};
    for (std::size_t i = 0; i < 8; ++i) { state[i] = sha256_h0[i]; }

    // Process all complete 64-byte blocks.
    std::size_t offset = 0;
    while (msg_len - offset >= 64) {
        sha256_compress(state, msg + offset);
        offset += 64;
    }

    // Build the final padded block(s).
    alignas(64) std::array<uint8_t, 128> pad{};
    const std::size_t tail = msg_len - offset;
    if (tail > 0) { std::memcpy(pad.data(), msg + offset, tail); }
    pad[tail] = 0x80U;

    // Append bit-length as big-endian uint64 in the last 8 bytes.
    const uint64_t bit_len_be = std::byteswap(static_cast<uint64_t>(msg_len) * 8U);
    if (tail < 56) {
        std::memcpy(pad.data() + 56, &bit_len_be, 8);
        sha256_compress(state, pad.data());
    } else {
        std::memcpy(pad.data() + 120, &bit_len_be, 8);
        sha256_compress(state, pad.data());
        sha256_compress(state, pad.data() + 64);
    }

    // Serialise state as big-endian bytes.
    for (std::size_t i = 0; i < 8; ++i) {
        const uint32_t w = std::byteswap(state[i]);
        std::memcpy(out.data() + (i * 4), &w, 4);
    }
}

}  // namespace arm_asm::detail
