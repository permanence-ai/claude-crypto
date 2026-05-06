// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Permanence AI

#pragma once

// Keccak-f[1600] permutation (24 rounds) — pure scalar 64-bit implementation.
//
// All 25 state lanes remain in named uint64_t scalar registers throughout each
// round.  No SIMD vector types are used.
//
// ρ+π is fully unrolled into 25 named locals with compile-time rotation
// constants, so the compiler emits one ROR per lane.
// χ uses A'[x][y] = B[x][y] ^ (~B[(x+1)%5][y] & B[(x+2)%5][y]).
//
// State convention: flat array of 25 uint64_t lanes in little-endian byte
// order, indexed as state[x + 5*y].

#include <cstdint>

#include "defs.hpp"


namespace ia_asm::detail {

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

// Rotate left by N bits; N must be a compile-time constant so the compiler
// emits a single ROR/ROL instruction.
template<int N>
static inline uint64_t krotl(uint64_t x) noexcept {
    static_assert(N > 0 && N < 64);
    return (x << static_cast<unsigned>(N)) | (x >> static_cast<unsigned>(64 - N));
}


// Keccak-f[1600] permutation: 24 rounds of θ + ρ + π + χ + ι.
//
// Pure scalar: all 25 state lanes stay in uint64_t named registers.
// ρ+π is fully unrolled with compile-time rotation constants (one ROR each).
// χ uses scalar bitwise NOT-AND: a ^ (~b & c).
[[gnu::target("aes,sha")]]
inline void keccak_f1600(uint64_t state[25]) noexcept // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
{
    for (const uint64_t rc : keccak_rc) {

        // ----------------------------------------------------------------
        // θ — column parity then D correction.
        // C[x] = XOR of column x across all 5 rows.
        // D[x] = C[x-1] ^ ROT(C[x+1], 1)
        // ----------------------------------------------------------------
        const uint64_t c0 = state[ 0] ^ state[ 5] ^ state[10] ^ state[15] ^ state[20];
        const uint64_t c1 = state[ 1] ^ state[ 6] ^ state[11] ^ state[16] ^ state[21];
        const uint64_t c2 = state[ 2] ^ state[ 7] ^ state[12] ^ state[17] ^ state[22];
        const uint64_t c3 = state[ 3] ^ state[ 8] ^ state[13] ^ state[18] ^ state[23];
        const uint64_t c4 = state[ 4] ^ state[ 9] ^ state[14] ^ state[19] ^ state[24];

        const uint64_t d0 = c4 ^ krotl<1>(c1);
        const uint64_t d1 = c0 ^ krotl<1>(c2);
        const uint64_t d2 = c1 ^ krotl<1>(c3);
        const uint64_t d3 = c2 ^ krotl<1>(c4);
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
        // χ — A'[x][y] = B[x][y] ^ (~B[(x+1)%5][y] & B[(x+2)%5][y])
        // ----------------------------------------------------------------

        // Row 0: b00 b01 b02 b03 b04
        state[ 0] = b00 ^ (~b01 & b02);
        state[ 1] = b01 ^ (~b02 & b03);
        state[ 2] = b02 ^ (~b03 & b04);
        state[ 3] = b03 ^ (~b04 & b00);
        state[ 4] = b04 ^ (~b00 & b01);

        // Row 1: b05 b06 b07 b08 b09
        state[ 5] = b05 ^ (~b06 & b07);
        state[ 6] = b06 ^ (~b07 & b08);
        state[ 7] = b07 ^ (~b08 & b09);
        state[ 8] = b08 ^ (~b09 & b05);
        state[ 9] = b09 ^ (~b05 & b06);

        // Row 2: b10 b11 b12 b13 b14
        state[10] = b10 ^ (~b11 & b12);
        state[11] = b11 ^ (~b12 & b13);
        state[12] = b12 ^ (~b13 & b14);
        state[13] = b13 ^ (~b14 & b10);
        state[14] = b14 ^ (~b10 & b11);

        // Row 3: b15 b16 b17 b18 b19
        state[15] = b15 ^ (~b16 & b17);
        state[16] = b16 ^ (~b17 & b18);
        state[17] = b17 ^ (~b18 & b19);
        state[18] = b18 ^ (~b19 & b15);
        state[19] = b19 ^ (~b15 & b16);

        // Row 4: b20 b21 b22 b23 b24
        state[20] = b20 ^ (~b21 & b22);
        state[21] = b21 ^ (~b22 & b23);
        state[22] = b22 ^ (~b23 & b24);
        state[23] = b23 ^ (~b24 & b20);
        state[24] = b24 ^ (~b20 & b21);

        // ----------------------------------------------------------------
        // ι — XOR round constant into lane [0,0].
        // ----------------------------------------------------------------
        state[0] ^= rc;
    }
}

}  // namespace ia_asm::detail
