/*
Copyright Permanence AI, 2026. All rights reserved.

*/

#pragma once

// Keccak-f[1600] permutation (24 rounds) using ARMv8.2 SHA3 extension.
//
// ARM SHA3 instructions used:
//   veor3q_u64(a,b,c)     = a ^ b ^ c          — θ column parity (3-way XOR)
//   vrax1q_u64(a,b)       = a ^ ROT(b,1)        — θ D correction per column pair
//   vbcaxq_u64(a,b,c)     = a ^ (b & ~c)        — χ non-linear mixing per row
//
// ρ+π is fully unrolled into 25 explicit named variables.  Every rotation
// amount is a compile-time constant so the compiler emits a single ROR
// instruction per lane (vs. a runtime-indexed loop that cannot use ROR).
// The intermediate B array is eliminated; named locals stay in registers.
// χ is unrolled over 5 explicit rows, each using vbcaxq_u64 for pairs.
//
// State convention: flat array of 25 uint64_t lanes in little-endian byte
// order, indexed as state[x + 5*y].

#include <arm_neon.h>
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

// Rotate left by n bits; n must be a compile-time constant so the compiler
// emits a single ROR instruction on AArch64.
template<int N>
static inline uint64_t krotl(uint64_t x) noexcept {
    static_assert(N > 0 && N < 64);
    return (x << static_cast<unsigned>(N)) | (x >> static_cast<unsigned>(64 - N));
}


// Keccak-f[1600] permutation: 24 rounds of θ + ρ + π + χ + ι.
//
// ρ+π is fully unrolled: each of the 25 lanes is a named local with a
// compile-time rotation constant, so the compiler emits one ROR per lane
// instead of a runtime table-indexed loop.  The B[25] intermediate array
// is eliminated — all 25 values live in named registers throughout χ.
[[gnu::target("sha3,neon")]]
inline void keccak_f1600(uint64_t state[25]) noexcept // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
{
    for (const uint64_t rc : keccak_rc) {

        // ----------------------------------------------------------------
        // θ — column parity then D correction.
        // C[x] = XOR of column x across all 5 rows.
        // D[x] = C[x-1] ^ ROT(C[x+1], 1)
        // ----------------------------------------------------------------
        const uint64x2_t c01 = veorq_u64(
            veor3q_u64(
                uint64x2_t{state[ 0], state[ 1]},
                uint64x2_t{state[ 5], state[ 6]},
                uint64x2_t{state[10], state[11]}),
            veorq_u64(
                uint64x2_t{state[15], state[16]},
                uint64x2_t{state[20], state[21]}));

        const uint64x2_t c23 = veorq_u64(
            veor3q_u64(
                uint64x2_t{state[ 2], state[ 3]},
                uint64x2_t{state[ 7], state[ 8]},
                uint64x2_t{state[12], state[13]}),
            veorq_u64(
                uint64x2_t{state[17], state[18]},
                uint64x2_t{state[22], state[23]}));

        const uint64_t c0 = vgetq_lane_u64(c01, 0);
        const uint64_t c1 = vgetq_lane_u64(c01, 1);
        const uint64_t c2 = vgetq_lane_u64(c23, 0);
        const uint64_t c3 = vgetq_lane_u64(c23, 1);
        const uint64_t c4 = state[4] ^ state[9] ^ state[14] ^ state[19] ^ state[24];

        // vrax1q_u64(a,b) = a ^ ROT(b, 1) — D[0..3] as two pairs.
        const uint64x2_t d01 = vrax1q_u64(uint64x2_t{c4, c0}, uint64x2_t{c1, c2});
        const uint64x2_t d23 = vrax1q_u64(uint64x2_t{c1, c2}, uint64x2_t{c3, c4});
        const uint64_t d0 = vgetq_lane_u64(d01, 0);
        const uint64_t d1 = vgetq_lane_u64(d01, 1);
        const uint64_t d2 = vgetq_lane_u64(d23, 0);
        const uint64_t d3 = vgetq_lane_u64(d23, 1);
        const uint64_t d4 = c3 ^ krotl<1>(c0);

        // ----------------------------------------------------------------
        // ρ+π — fully unrolled.
        //
        // Mapping: B[pi[s]] = ROT(state[s] ^ D[s%5], rho[s])
        // Named as b_XY where XY is the destination index in the flat array.
        //
        // s  src  dst(pi)  D-col  rho
        //  0   0    0       0      0  — identity, no rotate
        //  1   1   10       1      1
        //  2   2   20       2     62
        //  3   3    5       3     28
        //  4   4   15       4     27
        //  5   5   16       0     36
        //  6   6    1       1     44
        //  7   7   11       2      6
        //  8   8   21       3     55
        //  9   9    6       4     20
        // 10  10    7       0      3
        // 11  11   17       1     10
        // 12  12    2       2     43
        // 13  13   12       3     25
        // 14  14   22       4     39
        // 15  15   23       0     41
        // 16  16    8       1     45
        // 17  17   18       2     15
        // 18  18    3       3     21
        // 19  19   13       4      8
        // 20  20   14       0     18
        // 21  21   24       1      2
        // 22  22    9       2     61
        // 23  23   19       3     56
        // 24  24    4       4     14
        // ----------------------------------------------------------------
        const uint64_t b00 =          state[ 0] ^ d0;           // rho= 0
        const uint64_t b10 = krotl< 1>(state[ 1] ^ d1);
        const uint64_t b20 = krotl<62>(state[ 2] ^ d2);
        const uint64_t b05 = krotl<28>(state[ 3] ^ d3);
        const uint64_t b15 = krotl<27>(state[ 4] ^ d4);
        const uint64_t b16 = krotl<36>(state[ 5] ^ d0);
        const uint64_t b01 = krotl<44>(state[ 6] ^ d1);
        const uint64_t b11 = krotl< 6>(state[ 7] ^ d2);
        const uint64_t b21 = krotl<55>(state[ 8] ^ d3);
        const uint64_t b06 = krotl<20>(state[ 9] ^ d4);
        const uint64_t b07 = krotl< 3>(state[10] ^ d0);
        const uint64_t b17 = krotl<10>(state[11] ^ d1);
        const uint64_t b02 = krotl<43>(state[12] ^ d2);
        const uint64_t b12 = krotl<25>(state[13] ^ d3);
        const uint64_t b22 = krotl<39>(state[14] ^ d4);
        const uint64_t b23 = krotl<41>(state[15] ^ d0);
        const uint64_t b08 = krotl<45>(state[16] ^ d1);
        const uint64_t b18 = krotl<15>(state[17] ^ d2);
        const uint64_t b03 = krotl<21>(state[18] ^ d3);
        const uint64_t b13 = krotl< 8>(state[19] ^ d4);
        const uint64_t b14 = krotl<18>(state[20] ^ d0);
        const uint64_t b24 = krotl< 2>(state[21] ^ d1);
        const uint64_t b09 = krotl<61>(state[22] ^ d2);
        const uint64_t b19 = krotl<56>(state[23] ^ d3);
        const uint64_t b04 = krotl<14>(state[24] ^ d4);

        // ----------------------------------------------------------------
        // χ — A'[x][y] = B[x][y] ^ (B[(x+2)%5][y] & ~B[(x+1)%5][y])
        //             = vbcaxq_u64(B[x][y], B[(x+2)%5][y], B[(x+1)%5][y])
        // Five rows, each processed as two NEON pairs + one scalar.
        // ----------------------------------------------------------------

        // Row 0: b00 b01 b02 b03 b04
        const uint64x2_t r0_n01 = vbcaxq_u64(uint64x2_t{b00,b01}, uint64x2_t{b02,b03}, uint64x2_t{b01,b02});
        const uint64x2_t r0_n23 = vbcaxq_u64(uint64x2_t{b02,b03}, uint64x2_t{b04,b00}, uint64x2_t{b03,b04});
        state[ 0] = vgetq_lane_u64(r0_n01, 0);
        state[ 1] = vgetq_lane_u64(r0_n01, 1);
        state[ 2] = vgetq_lane_u64(r0_n23, 0);
        state[ 3] = vgetq_lane_u64(r0_n23, 1);
        state[ 4] = b04 ^ (b01 & ~b00);

        // Row 1: b05 b06 b07 b08 b09
        const uint64x2_t r1_n01 = vbcaxq_u64(uint64x2_t{b05,b06}, uint64x2_t{b07,b08}, uint64x2_t{b06,b07});
        const uint64x2_t r1_n23 = vbcaxq_u64(uint64x2_t{b07,b08}, uint64x2_t{b09,b05}, uint64x2_t{b08,b09});
        state[ 5] = vgetq_lane_u64(r1_n01, 0);
        state[ 6] = vgetq_lane_u64(r1_n01, 1);
        state[ 7] = vgetq_lane_u64(r1_n23, 0);
        state[ 8] = vgetq_lane_u64(r1_n23, 1);
        state[ 9] = b09 ^ (b06 & ~b05);

        // Row 2: b10 b11 b12 b13 b14
        const uint64x2_t r2_n01 = vbcaxq_u64(uint64x2_t{b10,b11}, uint64x2_t{b12,b13}, uint64x2_t{b11,b12});
        const uint64x2_t r2_n23 = vbcaxq_u64(uint64x2_t{b12,b13}, uint64x2_t{b14,b10}, uint64x2_t{b13,b14});
        state[10] = vgetq_lane_u64(r2_n01, 0);
        state[11] = vgetq_lane_u64(r2_n01, 1);
        state[12] = vgetq_lane_u64(r2_n23, 0);
        state[13] = vgetq_lane_u64(r2_n23, 1);
        state[14] = b14 ^ (b11 & ~b10);

        // Row 3: b15 b16 b17 b18 b19
        const uint64x2_t r3_n01 = vbcaxq_u64(uint64x2_t{b15,b16}, uint64x2_t{b17,b18}, uint64x2_t{b16,b17});
        const uint64x2_t r3_n23 = vbcaxq_u64(uint64x2_t{b17,b18}, uint64x2_t{b19,b15}, uint64x2_t{b18,b19});
        state[15] = vgetq_lane_u64(r3_n01, 0);
        state[16] = vgetq_lane_u64(r3_n01, 1);
        state[17] = vgetq_lane_u64(r3_n23, 0);
        state[18] = vgetq_lane_u64(r3_n23, 1);
        state[19] = b19 ^ (b16 & ~b15);

        // Row 4: b20 b21 b22 b23 b24
        const uint64x2_t r4_n01 = vbcaxq_u64(uint64x2_t{b20,b21}, uint64x2_t{b22,b23}, uint64x2_t{b21,b22});
        const uint64x2_t r4_n23 = vbcaxq_u64(uint64x2_t{b22,b23}, uint64x2_t{b24,b20}, uint64x2_t{b23,b24});
        state[20] = vgetq_lane_u64(r4_n01, 0);
        state[21] = vgetq_lane_u64(r4_n01, 1);
        state[22] = vgetq_lane_u64(r4_n23, 0);
        state[23] = vgetq_lane_u64(r4_n23, 1);
        state[24] = b24 ^ (b21 & ~b20);

        // ----------------------------------------------------------------
        // ι — XOR round constant into lane [0,0].
        // ----------------------------------------------------------------
        state[0] ^= rc;
    }
}

}  // namespace arm_asm::detail
