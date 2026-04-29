/*
Copyright Permanence AI, 2026. All rights reserved.

*/

#pragma once

// Keccak-f[1600] permutation (24 rounds) using ARMv8.2 SHA3 extension.
//
// Four ARM SHA3 instructions replace compound scalar sequences:
//   veor3q_u64(a,b,c)     = a ^ b ^ c          — θ column parity (3-way XOR)
//   vrax1q_u64(a,b)       = a ^ ROT(b,1)        — θ D correction per column pair
//   vbcaxq_u64(a,b,c)     = a ^ (b & ~c)        — χ non-linear mixing per row
//
// The ρ+π step uses a scalar lookup table (one rotation per lane, all
// different) so there is no benefit from vxarq_u64 (needs compile-time imm).
//
// State convention: flat array of 25 uint64_t lanes in little-endian byte
// order, indexed as state[x + 5*y].

#include <arm_neon.h>
#include <array>
#include <cstddef>
#include <cstdint>

#include "defs.hpp"


namespace arm_asm::detail {

// Keccak-f[1600] round constants (ι step).
inline constexpr uint64_t keccak_rc[24] = { // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL,
};

// ρ rotation amounts indexed by flat state position (x + 5*y).
inline constexpr int keccak_rho[25] = { // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
     0,  1, 62, 28, 27,
    36, 44,  6, 55, 20,
     3, 10, 43, 25, 39,
    41, 45, 15, 21,  8,
    18,  2, 61, 56, 14,
};

// π permutation: keccak_pi[src] = dst.
// B[dst] = ROT(A[src] ^ D[src%5], rho[src])  (combined θ+ρ+π).
inline constexpr int keccak_pi[25] = { // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
     0, 10, 20,  5, 15,
    16,  1, 11, 21,  6,
     7, 17,  2, 12, 22,
    23,  8, 18,  3, 13,
    14, 24,  9, 19,  4,
};

// Rotate left by n bits (0 ≤ n < 64); n=0 is a no-op.
static inline uint64_t keccak_rotl(uint64_t x, int n) noexcept {
    if (n == 0) { return x; }
    return (x << static_cast<unsigned>(n)) | (x >> static_cast<unsigned>(64 - n));
}


// Keccak-f[1600] permutation: 24 rounds of θ + ρ + π + χ + ι.
[[gnu::target("sha3,neon")]]
inline void keccak_f1600(uint64_t state[25]) noexcept // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
{
    for (int rnd = 0; rnd < 24; ++rnd) {

        // ----------------------------------------------------------------
        // θ — column parity C[x] = XOR of all 5 rows in column x.
        //     D[x] = C[x-1] ^ ROT(C[x+1], 1)
        //     A'[x][y] = A[x][y] ^ D[x]
        //
        // Process columns as pairs using veor3q_u64 (3-way XOR) and veorq.
        // ----------------------------------------------------------------

        // C[0], C[1]: columns 0 and 1 packed as lane-0 and lane-1.
        const uint64x2_t c01 = veorq_u64(
            veor3q_u64(
                uint64x2_t{state[ 0], state[ 1]},
                uint64x2_t{state[ 5], state[ 6]},
                uint64x2_t{state[10], state[11]}),
            veorq_u64(
                uint64x2_t{state[15], state[16]},
                uint64x2_t{state[20], state[21]}));

        // C[2], C[3]
        const uint64x2_t c23 = veorq_u64(
            veor3q_u64(
                uint64x2_t{state[ 2], state[ 3]},
                uint64x2_t{state[ 7], state[ 8]},
                uint64x2_t{state[12], state[13]}),
            veorq_u64(
                uint64x2_t{state[17], state[18]},
                uint64x2_t{state[22], state[23]}));

        // C[4] scalar
        const uint64_t c4 = state[4] ^ state[9] ^ state[14] ^ state[19] ^ state[24];

        // Extract scalars for vrax1q_u64 inputs.
        const uint64_t c0 = vgetq_lane_u64(c01, 0);
        const uint64_t c1 = vgetq_lane_u64(c01, 1);
        const uint64_t c2 = vgetq_lane_u64(c23, 0);
        const uint64_t c3 = vgetq_lane_u64(c23, 1);

        // vrax1q_u64(a,b) = {a[0] ^ ROT(b[0],1), a[1] ^ ROT(b[1],1)}
        // D[0] = C[4] ^ ROT(C[1],1),  D[1] = C[0] ^ ROT(C[2],1)
        const uint64x2_t d01 = vrax1q_u64(uint64x2_t{c4, c0}, uint64x2_t{c1, c2});
        // D[2] = C[1] ^ ROT(C[3],1),  D[3] = C[2] ^ ROT(C[4],1)
        const uint64x2_t d23 = vrax1q_u64(uint64x2_t{c1, c2}, uint64x2_t{c3, c4});
        // D[4] = C[3] ^ ROT(C[0],1)  — scalar
        const uint64_t d4 = c3 ^ keccak_rotl(c0, 1);

        const std::array<uint64_t, 5> D = {
            vgetq_lane_u64(d01, 0),
            vgetq_lane_u64(d01, 1),
            vgetq_lane_u64(d23, 0),
            vgetq_lane_u64(d23, 1),
            d4,
        };

        // ----------------------------------------------------------------
        // ρ+π — B[keccak_pi[s]] = ROT(A[s] ^ D[s%5], keccak_rho[s])
        // Each lane has a different rotation amount so we use scalar ROT.
        // ----------------------------------------------------------------
        std::array<uint64_t, 25> B{};
        for (int s = 0; s < 25; ++s) {
            // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
            B[static_cast<std::size_t>(keccak_pi[s])] = keccak_rotl(state[static_cast<std::size_t>(s)] ^ D[static_cast<std::size_t>(s) % 5], keccak_rho[s]); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
        }

        // ----------------------------------------------------------------
        // χ — A'[x][y] = B[x][y] ^ (B[(x+2)%5][y] & ~B[(x+1)%5][y])
        //             = vbcaxq_u64(B[x][y], B[(x+2)%5][y], B[(x+1)%5][y])
        //
        // Process each row as two pairs + one scalar.
        // ----------------------------------------------------------------
        for (std::size_t y = 0; y < 5; ++y) {
            const std::size_t base = y * 5;
            const uint64_t b0 = B[base + 0]; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
            const uint64_t b1 = B[base + 1]; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
            const uint64_t b2 = B[base + 2]; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
            const uint64_t b3 = B[base + 3]; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
            const uint64_t b4 = B[base + 4]; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)

            // {n0, n1} = vbcaxq_u64({b0,b1}, {b2,b3}, {b1,b2})
            //          = {b0 ^ (b2 & ~b1), b1 ^ (b3 & ~b2)}
            const uint64x2_t n01 = vbcaxq_u64(
                uint64x2_t{b0, b1}, uint64x2_t{b2, b3}, uint64x2_t{b1, b2});

            // {n2, n3} = vbcaxq_u64({b2,b3}, {b4,b0}, {b3,b4})
            //          = {b2 ^ (b4 & ~b3), b3 ^ (b0 & ~b4)}
            const uint64x2_t n23 = vbcaxq_u64(
                uint64x2_t{b2, b3}, uint64x2_t{b4, b0}, uint64x2_t{b3, b4});

            // n4 = b4 ^ (b1 & ~b0)
            const uint64_t n4 = b4 ^ (b1 & ~b0);

            state[base + 0] = vgetq_lane_u64(n01, 0); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index,cppcoreguidelines-pro-bounds-pointer-arithmetic)
            state[base + 1] = vgetq_lane_u64(n01, 1); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index,cppcoreguidelines-pro-bounds-pointer-arithmetic)
            state[base + 2] = vgetq_lane_u64(n23, 0); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index,cppcoreguidelines-pro-bounds-pointer-arithmetic)
            state[base + 3] = vgetq_lane_u64(n23, 1); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index,cppcoreguidelines-pro-bounds-pointer-arithmetic)
            state[base + 4] = n4;                      // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index,cppcoreguidelines-pro-bounds-pointer-arithmetic)
        }

        // ----------------------------------------------------------------
        // ι — XOR round constant into lane [0,0].
        // ----------------------------------------------------------------
        state[0] ^= keccak_rc[rnd]; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    }
}

}  // namespace arm_asm::detail
