/*
Copyright Permanence AI, 2026. All rights reserved.

*/

#pragma once

// SHA-512 and SHA-384 — pure scalar 64-bit implementation.
//
// There is no Intel SHA-512 instruction extension (only SHA-256 NI exists in
// Intel ISA extensions), so this is an unrolled scalar C++ implementation.
// The compiler will map uint64_t operations to 64-bit GP registers on x86_64.
//
// Constant-time by construction: no secret-dependent branches or memory
// accesses; all operations are simple integer arithmetic.

#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "defs.hpp"


namespace ia_asm::detail {

// SHA-512 initial hash values — fractional parts of sqrt of first 8 primes.
inline constexpr uint64_t sha512_h0[8] = { // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL,
};

// SHA-384 initial hash values — fractional parts of sqrt of 9th–16th primes.
inline constexpr uint64_t sha384_h0[8] = { // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    0xcbbb9d5dc1059ed8ULL, 0x629a292a367cd507ULL,
    0x9159015a3070dd17ULL, 0x152fecd8f70e5939ULL,
    0x67332667ffc00b31ULL, 0x8eb44a8768581511ULL,
    0xdb0c2e0d64f98fa7ULL, 0x47b5481dbefa4fa4ULL,
};

// SHA-512 round constants — fractional parts of cbrt of first 80 primes.
inline constexpr uint64_t sha512_k[80] = { // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
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
inline void sha512_compress(uint64_t state[8], const uint8_t block[128]) noexcept // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays,readability-function-size)
{
    // Load message words; block is big-endian.
    uint64_t w[80]; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    for (std::size_t i = 0; i < 16; ++i) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        std::memcpy(&w[i], block + (i * 8), 8); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic,cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        w[i] = std::byteswap(w[i]);
    }

    // Message schedule: σ0 = ROTR(x,1) ^ ROTR(x,8) ^ SHR(x,7)
    //                   σ1 = ROTR(x,19) ^ ROTR(x,61) ^ SHR(x,6)
    for (std::size_t i = 16; i < 80; ++i) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        const uint64_t s0 = std::rotr(w[i - 15], 1U) ^ std::rotr(w[i - 15], 8U) ^ (w[i - 15] >> 7U); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        const uint64_t s1 = std::rotr(w[i -  2], 19U) ^ std::rotr(w[i -  2], 61U) ^ (w[i - 2] >> 6U); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        w[i] = w[i - 16] + s0 + w[i - 7] + s1; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    }

    uint64_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint64_t e = state[4], f = state[5], g = state[6], h = state[7];

    for (std::size_t t = 0; t < 80; ++t) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        // Σ1 = ROTR(e,14) ^ ROTR(e,18) ^ ROTR(e,41)
        const uint64_t sigma1 = std::rotr(e, 14) ^ std::rotr(e, 18) ^ std::rotr(e, 41); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        // Ch = (e & f) ^ (~e & g)
        const uint64_t ch     = (e & f) ^ (~e & g);
        const uint64_t t1     = h + sigma1 + ch + sha512_k[t] + w[t];

        // Σ0 = ROTR(a,28) ^ ROTR(a,34) ^ ROTR(a,39)
        const uint64_t sigma0 = std::rotr(a, 28) ^ std::rotr(a, 34) ^ std::rotr(a, 39); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        // Maj = (a & b) ^ (a & c) ^ (b & c)
        const uint64_t maj    = (a & b) ^ (a & c) ^ (b & c);
        const uint64_t t2     = sigma0 + maj;

        h = g; g = f; f = e;
        e = d + t1;
        d = c; c = b; b = a;
        a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}


// Full SHA-512 over an arbitrary-length message.
inline void sha512(const CryptoByte* msg, std::size_t msg_len,
                   CryptoByte out[64]) noexcept // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
{
    uint64_t state[8]; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    for (std::size_t i = 0; i < 8; ++i) { state[i] = sha512_h0[i]; }

    std::size_t offset = 0;
    while (msg_len - offset >= 128) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        sha512_compress(state, msg + offset); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        offset += 128; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    }

    alignas(128) uint8_t pad[256]{}; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays,cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    const std::size_t tail = msg_len - offset;
    if (tail > 0) { std::memcpy(pad, msg + offset, tail); } // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    pad[tail] = 0x80U;

    // SHA-512 appends 128-bit big-endian bit-length; high 64 bits are always 0.
    const uint64_t bit_len_be = std::byteswap(static_cast<uint64_t>(msg_len) * 8U); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    if (tail < 112) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        std::memcpy(pad + 120, &bit_len_be, 8); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers,cppcoreguidelines-pro-bounds-pointer-arithmetic)
        sha512_compress(state, pad);
    } else {
        std::memcpy(pad + 248, &bit_len_be, 8); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers,cppcoreguidelines-pro-bounds-pointer-arithmetic)
        sha512_compress(state, pad);
        sha512_compress(state, pad + 128); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers,cppcoreguidelines-pro-bounds-pointer-arithmetic)
    }

    for (std::size_t i = 0; i < 8; ++i) {
        const uint64_t w = std::byteswap(state[i]);
        std::memcpy(out + (i * 8), &w, 8); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers,cppcoreguidelines-pro-bounds-pointer-arithmetic)
    }
}

// Full SHA-384 over an arbitrary-length message (same compression, different IV, truncated output).
inline void sha384(const CryptoByte* msg, std::size_t msg_len,
                   CryptoByte out[48]) noexcept // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
{
    uint64_t state[8]; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    for (std::size_t i = 0; i < 8; ++i) { state[i] = sha384_h0[i]; }

    std::size_t offset = 0;
    while (msg_len - offset >= 128) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        sha512_compress(state, msg + offset); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        offset += 128; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    }

    alignas(128) uint8_t pad[256]{}; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays,cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    const std::size_t tail = msg_len - offset;
    if (tail > 0) { std::memcpy(pad, msg + offset, tail); } // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    pad[tail] = 0x80U;

    const uint64_t bit_len_be = std::byteswap(static_cast<uint64_t>(msg_len) * 8U); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    if (tail < 112) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        std::memcpy(pad + 120, &bit_len_be, 8); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers,cppcoreguidelines-pro-bounds-pointer-arithmetic)
        sha512_compress(state, pad);
    } else {
        std::memcpy(pad + 248, &bit_len_be, 8); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers,cppcoreguidelines-pro-bounds-pointer-arithmetic)
        sha512_compress(state, pad);
        sha512_compress(state, pad + 128); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers,cppcoreguidelines-pro-bounds-pointer-arithmetic)
    }

    // Output only first 48 bytes (6 × 8).
    for (std::size_t i = 0; i < 6; ++i) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        const uint64_t w = std::byteswap(state[i]);
        std::memcpy(out + (i * 8), &w, 8); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers,cppcoreguidelines-pro-bounds-pointer-arithmetic)
    }
}

}  // namespace ia_asm::detail
