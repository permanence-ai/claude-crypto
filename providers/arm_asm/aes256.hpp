// SPDX-License-Identifier: Apache-2.0

#pragma once

// AES-256 key expansion and single-block encryption using ARMv8 AES
// crypto extensions.
//
// Key expansion (FIPS 197 §5.2):
//   AES-256 has Nk=8, Nr=14.  The schedule produces 15 round keys × 16 bytes.
//   The expansion loop uses vaeseq_u8(zero, w) to apply SubBytes (ShiftRows on
//   the zero register is a no-op for the first row, which is all we use).
//   RotWord is a 32-bit left rotate by 8.  The key schedule is identical to the
//   software version; only SubBytes is hardware-accelerated.
//
// Block encrypt (FIPS 197 §5.1):
//   13 rounds of vaeseq_u8 + vaesmcq_u8, then one final vaeseq_u8 + XOR.
//   Constant-time by construction: the intrinsics have no data-dependent
//   branches or memory accesses.
//
// Rcon table: 10 values needed for AES-256 key schedule (rcon[i] = x^i in
// GF(2^8), where x=0x02).  Only rcon[0..6] are used for AES-256.

#include <arm_neon.h>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "defs.hpp"


namespace arm_asm::detail {

// AES-256: 15 round keys, each 16 bytes.
constexpr std::size_t aes256_round_key_count = 15;
constexpr std::size_t aes256_round_key_bytes = 16;
constexpr std::size_t aes256_schedule_bytes  = aes256_round_key_count * aes256_round_key_bytes;

using Aes256Schedule = std::array<uint8_t, aes256_schedule_bytes>;


[[nodiscard]]
[[gnu::target("aes,neon")]]
inline uint32_t aes_sub_word(uint32_t w) noexcept {
    // Apply SubBytes to each byte of w using vaeseq_u8 on a zero block.
    // vaeseq_u8 does AddRoundKey(zero) + SubBytes + ShiftRows.
    // ShiftRows leaves the first row unchanged, so byte 0 of the result
    // is SubBytes(byte 0 of w), etc. — which is what we want for the
    // four bytes of a single word treated as the first column.
    const uint8x16_t zero = vdupq_n_u8(0);
    uint8x16_t v = vreinterpretq_u8_u32(vdupq_n_u32(w));
    v = vaeseq_u8(zero, v);
    return vgetq_lane_u32(vreinterpretq_u32_u8(v), 0);
}

[[nodiscard]]
static inline uint32_t aes_rot_word(uint32_t w) noexcept {
    return (w << (32U - 8U)) | (w >> 8U);
}

// Expand a 256-bit key into the AES-256 round-key schedule.
// key must point to 32 bytes; out receives 15 × 16 bytes (aes256_schedule_bytes).
[[gnu::target("aes,neon")]]
inline void aes256_key_expand(const CryptoByte key[32], Aes256Schedule& sched) noexcept
{
    // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    static constexpr uint8_t rcon[7] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40 };

    // The schedule is built as an array of 32-bit words, 60 words total.
    // Round key i occupies words [4i .. 4i+3].  We need 15 round keys → 60 words.
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    uint32_t w[60]{};

    // W[0..7] = key bytes directly.
    for (std::size_t i = 0; i < 8; ++i) {
        std::memcpy(&w[i], key + (i * 4), 4);
    }

    for (std::size_t i = 8; i < 60; ++i) {
        uint32_t tmp = w[i - 1];
        if (i % 8 == 0) {
            tmp = aes_sub_word(aes_rot_word(tmp)) ^ rcon[(i / 8U) - 1U]; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
        } else if (i % 8 == 4) {
            tmp = aes_sub_word(tmp);
        }
        w[i] = w[i - 8] ^ tmp;
    }

    // Pack words into the schedule byte array.
    for (std::size_t i = 0; i < aes256_round_key_count; ++i) {
        for (std::size_t j = 0; j < 4; ++j) {
            std::memcpy(sched.data() + (i * 16) + (j * 4), &w[(i * 4) + j], 4);
        }
    }
}


// Encrypt a single 16-byte block under the pre-expanded AES-256 schedule.
// The result is written back to block.
[[nodiscard]]
[[gnu::target("aes,neon")]]
inline uint8x16_t aes256_encrypt_block(uint8x16_t block,
                                       const Aes256Schedule& sched) noexcept
{
    const uint8_t* rk = sched.data();

    // Rounds 0–12: vaeseq_u8 (AddRoundKey, SubBytes, ShiftRows) + vaesmcq_u8 (MixColumns).
    // vaeseq_u8(block, round_key) combines AddRoundKey and SubBytes/ShiftRows atomically.
    block = vaeseq_u8(block, vld1q_u8(rk));       rk += 16; block = vaesmcq_u8(block);
    block = vaeseq_u8(block, vld1q_u8(rk));       rk += 16; block = vaesmcq_u8(block);
    block = vaeseq_u8(block, vld1q_u8(rk));       rk += 16; block = vaesmcq_u8(block);
    block = vaeseq_u8(block, vld1q_u8(rk));       rk += 16; block = vaesmcq_u8(block);
    block = vaeseq_u8(block, vld1q_u8(rk));       rk += 16; block = vaesmcq_u8(block);
    block = vaeseq_u8(block, vld1q_u8(rk));       rk += 16; block = vaesmcq_u8(block);
    block = vaeseq_u8(block, vld1q_u8(rk));       rk += 16; block = vaesmcq_u8(block);
    block = vaeseq_u8(block, vld1q_u8(rk));       rk += 16; block = vaesmcq_u8(block);
    block = vaeseq_u8(block, vld1q_u8(rk));       rk += 16; block = vaesmcq_u8(block);
    block = vaeseq_u8(block, vld1q_u8(rk));       rk += 16; block = vaesmcq_u8(block);
    block = vaeseq_u8(block, vld1q_u8(rk));       rk += 16; block = vaesmcq_u8(block);
    block = vaeseq_u8(block, vld1q_u8(rk));       rk += 16; block = vaesmcq_u8(block);
    block = vaeseq_u8(block, vld1q_u8(rk));       rk += 16; block = vaesmcq_u8(block);
    // Round 13: SubBytes + ShiftRows (AddRoundKey with rk[13]) — no MixColumns.
    block = vaeseq_u8(block, vld1q_u8(rk));       rk += 16;
    // Final AddRoundKey (round key 14).
    block = veorq_u8(block, vld1q_u8(rk));

    return block;
}

}  // namespace arm_asm::detail
