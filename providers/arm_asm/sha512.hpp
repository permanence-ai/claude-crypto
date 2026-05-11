// SPDX-License-Identifier: Apache-2.0

#pragma once

// SHA-512 and SHA-384 using ARMv8 SHA2 crypto extensions.
//
// Requires __ARM_FEATURE_SHA512 which is part of ARMv8.2-A+crypto
// (Apple Silicon M1 and later). The -march=armv8.2-a+crypto+sha3 flag in
// the provider CMakeLists sets this.
//
// Compression intrinsics (ARM Architecture Reference Manual H.8):
//   vsha512hq_u64(sum, vextq_u64(Xn,Xm,1), vextq_u64(Xp,Xn,1)):
//     where sum = {W[t]+K[t]+h, W[t+1]+K[t+1]+g} (g/h from the gh register,
//     with the two words swapped relative to W+K: vextq_u64(wk,wk,1) + gh)
//     result = intermed, the T1+T2 contribution for e,f
//   vsha512h2q_u64(intermed, cd, ab):
//     result = new contribution for e,f pair (the "majority" path)
//   The "Xm" pair is then updated: Xm = vaddq_u64(Xm, intermed)
//   The net effect rotates which pair plays the role of ab/cd/ef/gh over 4 rounds.
//
// Register roles cycle every 4 rounds (each round pair uses a fixed 4-step pattern):
//   Rounds 0,1:  intermed -> gh  (gh updated), cd += intermed
//   Rounds 2,3:  intermed -> ef  (ef updated), ab += intermed
//   Rounds 4,5:  intermed -> cd  (cd updated), gh += intermed
//   Rounds 6,7:  intermed -> ab  (ab updated), ef += intermed
//   Rounds 8,9:  same as 0,1 ...

#include <arm_neon.h>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>

#include "defs.hpp"


namespace arm_asm::detail {

// SHA-512 initial hash values — fractional parts of sqrt of first 8 primes.
inline constexpr std::array<uint64_t, 8> sha512_h0 = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL,
};

// SHA-384 initial hash values — fractional parts of sqrt of 9th–16th primes.
inline constexpr std::array<uint64_t, 8> sha384_h0 = {
    0xcbbb9d5dc1059ed8ULL, 0x629a292a367cd507ULL,
    0x9159015a3070dd17ULL, 0x152fecd8f70e5939ULL,
    0x67332667ffc00b31ULL, 0x8eb44a8768581511ULL,
    0xdb0c2e0d64f98fa7ULL, 0x47b5481dbefa4fa4ULL,
};

// SHA-512 round constants — fractional parts of cbrt of first 80 primes.
inline constexpr std::array<uint64_t, 80> sha512_k = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL,
    0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
    0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL,
    0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL,
    0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
    0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL,
    0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL,
    0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
    0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL,
    0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL,
    0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
    0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL,
    0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
    0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
    0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL,
    0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL,
    0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
    0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL,
    0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL,
    0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
    0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL,
};


// Process one 128-byte SHA-512 block.
// state[0..7] = {h0,..,h7}, updated in place.
// Message bytes are big-endian; load+byteswap is done here.
// Constant-time by construction: no secret-dependent branches or memory accesses.
//
// Two-round step pattern (cycles over 4 step types, indices mod 4):
//   step 0 (rounds 0,1,8,9,...): targets gh, complement cd
//   step 1 (rounds 2,3,10,11,...): targets ef, complement ab
//   step 2 (rounds 4,5,12,13,...): targets cd, complement gh
//   step 3 (rounds 6,7,14,15,...): targets ab, complement ef
//
// For each step:
//   initial_sum = sN + K[t..t+1]
//   sum = vextq_u64(initial_sum, initial_sum, 1) + <current_gh>
//   intermed = vsha512hq_u64(sum, vextq_u64(<ef>,<gh>,1), vextq_u64(<cd>,<ef>,1))
//   <new_gh_target> = vsha512h2q_u64(intermed, <cd>, <ab>)
//   <cd_complement> += intermed
// where <ef>,<gh>,<cd>,<ab> rotate through {ef,gh,cd,ab} each step.
[[gnu::target("sha3,neon")]]
inline void sha512_compress(std::span<uint64_t, 8> state, const uint8_t* block) noexcept // NOLINT(readability-function-size,readability-function-cognitive-complexity)
{
    uint64x2_t ab = vld1q_u64(state.data());
    uint64x2_t cd = vld1q_u64(state.data() + 2);
    uint64x2_t ef = vld1q_u64(state.data() + 4);
    uint64x2_t gh = vld1q_u64(state.data() + 6);
    const uint64x2_t ab0 = ab;
    const uint64x2_t cd0 = cd;
    const uint64x2_t ef0 = ef;
    const uint64x2_t gh0 = gh;

    // Load 16 message words (big-endian 64-bit) into 8 register pairs.
    uint64x2_t s0 = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(block)));
    uint64x2_t s1 = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(block + 16)));
    uint64x2_t s2 = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(block + 32)));
    uint64x2_t s3 = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(block + 48)));
    uint64x2_t s4 = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(block + 64)));
    uint64x2_t s5 = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(block + 80)));
    uint64x2_t s6 = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(block + 96)));
    uint64x2_t s7 = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(block + 112)));

    uint64x2_t initial_sum{};
    uint64x2_t sum{};
    uint64x2_t intermed{};

    // Rounds 0,1
    initial_sum = vaddq_u64(s0, vld1q_u64(sha512_k.data()));
    sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), gh);
    intermed = vsha512hq_u64(sum, vextq_u64(ef, gh, 1), vextq_u64(cd, ef, 1));
    gh = vsha512h2q_u64(intermed, cd, ab);
    cd = vaddq_u64(cd, intermed);

    // Rounds 2,3
    initial_sum = vaddq_u64(s1, vld1q_u64(sha512_k.data() + 2));
    sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), ef);
    intermed = vsha512hq_u64(sum, vextq_u64(cd, ef, 1), vextq_u64(ab, cd, 1));
    ef = vsha512h2q_u64(intermed, ab, gh);
    ab = vaddq_u64(ab, intermed);

    // Rounds 4,5
    initial_sum = vaddq_u64(s2, vld1q_u64(sha512_k.data() + 4));
    sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), cd);
    intermed = vsha512hq_u64(sum, vextq_u64(ab, cd, 1), vextq_u64(gh, ab, 1));
    cd = vsha512h2q_u64(intermed, gh, ef);
    gh = vaddq_u64(gh, intermed);

    // Rounds 6,7
    initial_sum = vaddq_u64(s3, vld1q_u64(sha512_k.data() + 6));
    sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), ab);
    intermed = vsha512hq_u64(sum, vextq_u64(gh, ab, 1), vextq_u64(ef, gh, 1));
    ab = vsha512h2q_u64(intermed, ef, cd);
    ef = vaddq_u64(ef, intermed);

    // Rounds 8,9
    initial_sum = vaddq_u64(s4, vld1q_u64(sha512_k.data() + 8));
    sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), gh);
    intermed = vsha512hq_u64(sum, vextq_u64(ef, gh, 1), vextq_u64(cd, ef, 1));
    gh = vsha512h2q_u64(intermed, cd, ab);
    cd = vaddq_u64(cd, intermed);

    // Rounds 10,11
    initial_sum = vaddq_u64(s5, vld1q_u64(sha512_k.data() + 10));
    sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), ef);
    intermed = vsha512hq_u64(sum, vextq_u64(cd, ef, 1), vextq_u64(ab, cd, 1));
    ef = vsha512h2q_u64(intermed, ab, gh);
    ab = vaddq_u64(ab, intermed);

    // Rounds 12,13
    initial_sum = vaddq_u64(s6, vld1q_u64(sha512_k.data() + 12));
    sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), cd);
    intermed = vsha512hq_u64(sum, vextq_u64(ab, cd, 1), vextq_u64(gh, ab, 1));
    cd = vsha512h2q_u64(intermed, gh, ef);
    gh = vaddq_u64(gh, intermed);

    // Rounds 14,15
    initial_sum = vaddq_u64(s7, vld1q_u64(sha512_k.data() + 14));
    sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), ab);
    intermed = vsha512hq_u64(sum, vextq_u64(gh, ab, 1), vextq_u64(ef, gh, 1));
    ab = vsha512h2q_u64(intermed, ef, cd);
    ef = vaddq_u64(ef, intermed);

    // Rounds 16..79: message schedule + compression, 8 pairs per loop iteration.
    for (std::size_t t = 16; t < 80; t += 16) {
        // Schedule: su0(sN, sN+1) then su1(sN, sN+7, vextq_u64(sN+4, sN+5, 1))
        s0 = vsha512su1q_u64(vsha512su0q_u64(s0, s1), s7, vextq_u64(s4, s5, 1));
        initial_sum = vaddq_u64(s0, vld1q_u64(sha512_k.data() + t));
        sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), gh);
        intermed = vsha512hq_u64(sum, vextq_u64(ef, gh, 1), vextq_u64(cd, ef, 1));
        gh = vsha512h2q_u64(intermed, cd, ab);
        cd = vaddq_u64(cd, intermed);

        s1 = vsha512su1q_u64(vsha512su0q_u64(s1, s2), s0, vextq_u64(s5, s6, 1));
        initial_sum = vaddq_u64(s1, vld1q_u64(sha512_k.data() + t + 2));
        sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), ef);
        intermed = vsha512hq_u64(sum, vextq_u64(cd, ef, 1), vextq_u64(ab, cd, 1));
        ef = vsha512h2q_u64(intermed, ab, gh);
        ab = vaddq_u64(ab, intermed);

        s2 = vsha512su1q_u64(vsha512su0q_u64(s2, s3), s1, vextq_u64(s6, s7, 1));
        initial_sum = vaddq_u64(s2, vld1q_u64(sha512_k.data() + t + 4));
        sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), cd);
        intermed = vsha512hq_u64(sum, vextq_u64(ab, cd, 1), vextq_u64(gh, ab, 1));
        cd = vsha512h2q_u64(intermed, gh, ef);
        gh = vaddq_u64(gh, intermed);

        s3 = vsha512su1q_u64(vsha512su0q_u64(s3, s4), s2, vextq_u64(s7, s0, 1));
        initial_sum = vaddq_u64(s3, vld1q_u64(sha512_k.data() + t + 6));
        sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), ab);
        intermed = vsha512hq_u64(sum, vextq_u64(gh, ab, 1), vextq_u64(ef, gh, 1));
        ab = vsha512h2q_u64(intermed, ef, cd);
        ef = vaddq_u64(ef, intermed);

        s4 = vsha512su1q_u64(vsha512su0q_u64(s4, s5), s3, vextq_u64(s0, s1, 1));
        initial_sum = vaddq_u64(s4, vld1q_u64(sha512_k.data() + t + 8));
        sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), gh);
        intermed = vsha512hq_u64(sum, vextq_u64(ef, gh, 1), vextq_u64(cd, ef, 1));
        gh = vsha512h2q_u64(intermed, cd, ab);
        cd = vaddq_u64(cd, intermed);

        s5 = vsha512su1q_u64(vsha512su0q_u64(s5, s6), s4, vextq_u64(s1, s2, 1));
        initial_sum = vaddq_u64(s5, vld1q_u64(sha512_k.data() + t + 10));
        sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), ef);
        intermed = vsha512hq_u64(sum, vextq_u64(cd, ef, 1), vextq_u64(ab, cd, 1));
        ef = vsha512h2q_u64(intermed, ab, gh);
        ab = vaddq_u64(ab, intermed);

        s6 = vsha512su1q_u64(vsha512su0q_u64(s6, s7), s5, vextq_u64(s2, s3, 1));
        initial_sum = vaddq_u64(s6, vld1q_u64(sha512_k.data() + t + 12));
        sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), cd);
        intermed = vsha512hq_u64(sum, vextq_u64(ab, cd, 1), vextq_u64(gh, ab, 1));
        cd = vsha512h2q_u64(intermed, gh, ef);
        gh = vaddq_u64(gh, intermed);

        s7 = vsha512su1q_u64(vsha512su0q_u64(s7, s0), s6, vextq_u64(s3, s4, 1));
        initial_sum = vaddq_u64(s7, vld1q_u64(sha512_k.data() + t + 14));
        sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), ab);
        intermed = vsha512hq_u64(sum, vextq_u64(gh, ab, 1), vextq_u64(ef, gh, 1));
        ab = vsha512h2q_u64(intermed, ef, cd);
        ef = vaddq_u64(ef, intermed);
    }

    vst1q_u64(state.data(),     vaddq_u64(ab, ab0));
    vst1q_u64(state.data() + 2, vaddq_u64(cd, cd0));
    vst1q_u64(state.data() + 4, vaddq_u64(ef, ef0));
    vst1q_u64(state.data() + 6, vaddq_u64(gh, gh0));
}


// Full SHA-512 over an arbitrary-length message.
// out must point to at least 64 bytes.
inline void sha512(const CryptoByte* msg, std::size_t msg_len,
                   std::span<CryptoByte, sha512_digest_bytes> out) noexcept
{
    std::array<uint64_t, 8> state{};
    for (std::size_t i = 0; i < 8; ++i) { state[i] = sha512_h0[i]; }

    std::size_t offset = 0;
    while (msg_len - offset >= sha512_block_bytes) {
        sha512_compress(state, msg + offset);
        offset += sha512_block_bytes;
    }

    // Build padded final block(s): 128-byte blocks, 128-bit BE length in last 16 bytes.
    alignas(sha512_block_bytes) std::array<CryptoByte, 2 * sha512_block_bytes> pad{};
    const std::size_t tail = msg_len - offset;
    if (tail > 0) { std::memcpy(pad.data(), msg + offset, tail); }
    pad[tail] = 0x80U;

    // Low 64 bits of the 128-bit big-endian bit-count (high 64 bits are always 0 here).
    const uint64_t bit_len_be = std::byteswap(static_cast<uint64_t>(msg_len) * 8U);
    if (tail < 112) {
        std::memcpy(pad.data() + 120, &bit_len_be, 8);  // bytes 112-119 = 0 (high), 120-127 = low
        sha512_compress(state, pad.data());
    } else {
        std::memcpy(pad.data() + 248, &bit_len_be, 8);
        sha512_compress(state, pad.data());
        sha512_compress(state, pad.data() + 128);
    }

    for (std::size_t i = 0; i < 8; ++i) {
        const uint64_t w = std::byteswap(state[i]);
        std::memcpy(out.data() + (i * 8), &w, 8);
    }
}


// SHA-384: same compression as SHA-512 but different initial state and 48-byte output.
inline void sha384(const CryptoByte* msg, std::size_t msg_len,
                   std::span<CryptoByte, sha384_digest_bytes> out) noexcept
{
    std::array<uint64_t, 8> state{};
    for (std::size_t i = 0; i < 8; ++i) { state[i] = sha384_h0[i]; }

    std::size_t offset = 0;
    while (msg_len - offset >= sha512_block_bytes) {
        sha512_compress(state, msg + offset);
        offset += sha512_block_bytes;
    }

    alignas(sha512_block_bytes) std::array<CryptoByte, 2 * sha512_block_bytes> pad{};
    const std::size_t tail = msg_len - offset;
    if (tail > 0) { std::memcpy(pad.data(), msg + offset, tail); }
    pad[tail] = 0x80U;

    const uint64_t bit_len_be = std::byteswap(static_cast<uint64_t>(msg_len) * 8U);
    if (tail < 112) {
        std::memcpy(pad.data() + 120, &bit_len_be, 8);
        sha512_compress(state, pad.data());
    } else {
        std::memcpy(pad.data() + 248, &bit_len_be, 8);
        sha512_compress(state, pad.data());
        sha512_compress(state, pad.data() + 128);
    }

    // SHA-384 output is the first 6 words (48 bytes).
    for (std::size_t i = 0; i < 6; ++i) {
        const uint64_t w = std::byteswap(state[i]);
        std::memcpy(out.data() + (i * 8), &w, 8);
    }
}

}  // namespace arm_asm::detail
