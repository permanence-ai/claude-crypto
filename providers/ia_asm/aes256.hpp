// SPDX-License-Identifier: Apache-2.0

#pragma once

// AES-256 key expansion and single-block encryption using Intel AES-NI.
//
// Key expansion (FIPS 197 §5.2):
//   AES-256 has Nk=8, Nr=14.  The schedule produces 15 round keys × 16 bytes.
//   _mm_aeskeygenassist_si128 extracts the SubWord/RotWord result.
//   _mm_shuffle_epi32 + _mm_slli_si128 reconstruct the XOR chain.
//
// Block encrypt (FIPS 197 §5.1):
//   13 rounds of _mm_aesenc_si128, then one _mm_aesenclast_si128.
//   Constant-time by construction: AES-NI instructions have no data-dependent
//   branches or memory accesses.

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <immintrin.h>
#include <span>

#include "defs.hpp"


namespace ia_asm::detail {

// AES-256: 15 round keys, each 16 bytes.
constexpr std::size_t aes256_round_key_count = 15;
constexpr std::size_t aes256_round_key_bytes = 16;
constexpr std::size_t aes256_schedule_bytes  = aes256_round_key_count * aes256_round_key_bytes;

using Aes256Schedule = std::array<uint8_t, aes256_schedule_bytes>;


// Helper: given xmm_rcon = _mm_aeskeygenassist_si128(prev, rcon), extract
// the KeyGenAssist result (lane 3 broadcast) and XOR with the previous word chain.
[[gnu::target("aes,sse4.1")]]
static inline __m128i aes256_keygen_helper(__m128i key, __m128i keygen_result) noexcept {
    // Broadcast lane 3 (the SubWord(RotWord(w)) result) to all lanes.
    keygen_result = _mm_shuffle_epi32(keygen_result, 0xFF);
    // XOR-chain: key ^= key<<32 ^= key<<64 ^= key<<96
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 8));
    return _mm_xor_si128(key, keygen_result);
}

// Helper for the "odd" AES-256 round keys (those derived from SubWord without RotWord).
[[gnu::target("aes,sse4.1")]]
static inline __m128i aes256_keygen_helper2(__m128i key, __m128i keygen_result) noexcept {
    keygen_result = _mm_shuffle_epi32(keygen_result, 0xAA); // lane 2
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 8));
    return _mm_xor_si128(key, keygen_result);
}


// Expand a 256-bit key into the AES-256 round-key schedule.
// key must point to 32 bytes; sched receives 15 × 16 bytes.
[[gnu::target("aes,sse4.1")]]
inline void aes256_key_expand(std::span<const CryptoByte, aes256_key_size_bytes> key, Aes256Schedule& sched) noexcept
{
    // Load the two 128-bit halves of the 256-bit key.
    __m128i k0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key.data())); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
    __m128i k1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key.data() + 16)); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)

    auto* rk = reinterpret_cast<__m128i*>(sched.data()); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)

    _mm_storeu_si128(rk + 0, k0); // round key 0
    _mm_storeu_si128(rk + 1, k1); // round key 1

    k0 = aes256_keygen_helper(k0, _mm_aeskeygenassist_si128(k1, 0x01));
    _mm_storeu_si128(rk + 2, k0);
    k1 = aes256_keygen_helper2(k1, _mm_aeskeygenassist_si128(k0, 0x00));
    _mm_storeu_si128(rk + 3, k1);

    k0 = aes256_keygen_helper(k0, _mm_aeskeygenassist_si128(k1, 0x02));
    _mm_storeu_si128(rk + 4, k0);
    k1 = aes256_keygen_helper2(k1, _mm_aeskeygenassist_si128(k0, 0x00));
    _mm_storeu_si128(rk + 5, k1);

    k0 = aes256_keygen_helper(k0, _mm_aeskeygenassist_si128(k1, 0x04));
    _mm_storeu_si128(rk + 6, k0);
    k1 = aes256_keygen_helper2(k1, _mm_aeskeygenassist_si128(k0, 0x00));
    _mm_storeu_si128(rk + 7, k1);

    k0 = aes256_keygen_helper(k0, _mm_aeskeygenassist_si128(k1, 0x08));
    _mm_storeu_si128(rk + 8, k0);
    k1 = aes256_keygen_helper2(k1, _mm_aeskeygenassist_si128(k0, 0x00));
    _mm_storeu_si128(rk + 9, k1);

    k0 = aes256_keygen_helper(k0, _mm_aeskeygenassist_si128(k1, 0x10));
    _mm_storeu_si128(rk + 10, k0);
    k1 = aes256_keygen_helper2(k1, _mm_aeskeygenassist_si128(k0, 0x00));
    _mm_storeu_si128(rk + 11, k1);

    k0 = aes256_keygen_helper(k0, _mm_aeskeygenassist_si128(k1, 0x20));
    _mm_storeu_si128(rk + 12, k0);
    k1 = aes256_keygen_helper2(k1, _mm_aeskeygenassist_si128(k0, 0x00));
    _mm_storeu_si128(rk + 13, k1);

    k0 = aes256_keygen_helper(k0, _mm_aeskeygenassist_si128(k1, 0x40));
    _mm_storeu_si128(rk + 14, k0);
}


// Encrypt a single 16-byte block under the pre-expanded AES-256 schedule.
[[nodiscard]]
[[gnu::target("aes")]]
inline __m128i aes256_encrypt_block(__m128i block, const Aes256Schedule& sched) noexcept
{
    const auto* rk = reinterpret_cast<const __m128i*>(sched.data()); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)

    block = _mm_xor_si128(block, _mm_loadu_si128(rk + 0));    // AddRoundKey(0)
    block = _mm_aesenc_si128(block, _mm_loadu_si128(rk + 1));  // Round 1
    block = _mm_aesenc_si128(block, _mm_loadu_si128(rk + 2));  // Round 2
    block = _mm_aesenc_si128(block, _mm_loadu_si128(rk + 3));  // Round 3
    block = _mm_aesenc_si128(block, _mm_loadu_si128(rk + 4));  // Round 4
    block = _mm_aesenc_si128(block, _mm_loadu_si128(rk + 5));  // Round 5
    block = _mm_aesenc_si128(block, _mm_loadu_si128(rk + 6));  // Round 6
    block = _mm_aesenc_si128(block, _mm_loadu_si128(rk + 7));  // Round 7
    block = _mm_aesenc_si128(block, _mm_loadu_si128(rk + 8));  // Round 8
    block = _mm_aesenc_si128(block, _mm_loadu_si128(rk + 9));  // Round 9
    block = _mm_aesenc_si128(block, _mm_loadu_si128(rk + 10)); // Round 10
    block = _mm_aesenc_si128(block, _mm_loadu_si128(rk + 11)); // Round 11
    block = _mm_aesenc_si128(block, _mm_loadu_si128(rk + 12)); // Round 12
    block = _mm_aesenc_si128(block, _mm_loadu_si128(rk + 13)); // Round 13
    block = _mm_aesenclast_si128(block, _mm_loadu_si128(rk + 14)); // Round 14 (final)

    return block;
}

}  // namespace ia_asm::detail
