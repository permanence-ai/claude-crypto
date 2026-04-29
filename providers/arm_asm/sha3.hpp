/*
Copyright Permanence AI, 2026. All rights reserved.

*/

#pragma once

// SHA3-256/384/512 sponge construction over Keccak-f[1600].
//
// All three variants share the same absorb/squeeze loop; they differ only in
// rate (bytes XOR'd per round) and output length:
//   SHA3-256: rate=136, capacity=64,  out=32
//   SHA3-384: rate=104, capacity=96,  out=48
//   SHA3-512: rate= 72, capacity=128, out=64
//
// Domain separator: 0x06 (SHA-3 FIPS 202 suffix "11" in little-endian bit order,
// combined with the multi-rate padding marker 0x01 → net byte = 0x06).
//
// Padding rule (FIPS 202 §B.2, pad10*1):
//   Append 0x06 at position msg_len % rate, then 0x80 at rate-1 of that block.
//   If both positions coincide (single byte remaining), write 0x86.
//
// State convention: flat array of 25 uint64_t lanes in little-endian byte order,
// compatible with keccak_f1600 in keccak.hpp.

#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "defs.hpp"
#include "keccak.hpp"


namespace arm_asm::detail {

// Number of lanes the sponge XORs per round = rate_bytes / 8.
// SHA3-256: 17, SHA3-384: 13, SHA3-512: 9.

// Incremental SHA-3 context.  Holds the 1600-bit Keccak state, a partial block
// buffer sized to the maximum rate (SHA3-256, 136 bytes), and state metadata.
struct Sha3Ctx {
    // NOLINT(misc-non-private-member-variables-in-classes) — plain aggregate.
    uint64_t    state[25]; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays,misc-non-private-member-variables-in-classes,cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    uint8_t     buf[136];  // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays,misc-non-private-member-variables-in-classes,cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    std::size_t rate_bytes; // NOLINT(misc-non-private-member-variables-in-classes)
    std::size_t out_bytes;  // NOLINT(misc-non-private-member-variables-in-classes)
    std::size_t buf_used;   // NOLINT(misc-non-private-member-variables-in-classes)

    void init(std::size_t rate, std::size_t out) noexcept {
        for (std::size_t i = 0; i < 25; ++i) { state[i] = 0; } // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        std::memset(buf, 0, sizeof(buf));
        rate_bytes = rate;
        out_bytes  = out;
        buf_used   = 0;
    }

    void update(const uint8_t* data, std::size_t len) noexcept {
        while (len > 0) {
            const std::size_t space = rate_bytes - buf_used;
            const std::size_t take  = len < space ? len : space;
            std::memcpy(buf + buf_used, data, take); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
            buf_used += take;
            data     += take; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
            len      -= take;
            if (buf_used == rate_bytes) {
                absorb_block();
                buf_used = 0;
            }
        }
    }

    // Apply SHA-3 padding and produce the digest in out[0..out_bytes).
    void finish(uint8_t* out) noexcept {
        // Pad10*1 with SHA-3 domain suffix 0x06.
        std::memset(buf + buf_used, 0, rate_bytes - buf_used);
        buf[buf_used]       = 0x06U; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
        buf[rate_bytes - 1] ^= 0x80U; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
        absorb_block();

        // Squeeze: output lanes are already in little-endian byte order on LE
        // hardware (Apple Silicon is LE), so write directly.
        for (std::size_t i = 0; i < out_bytes; ++i) {
            // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
            out[i] = static_cast<uint8_t>(state[i / 8] >> ((i % 8) * 8)); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        }
    }

private:
    void absorb_block() noexcept {
        // XOR the rate lanes into the state (little-endian byte order).
        const std::size_t lanes = rate_bytes / 8; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        for (std::size_t i = 0; i < lanes; ++i) {
            uint64_t word = 0;
            std::memcpy(&word, buf + i * 8, 8); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic,cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
            if constexpr (std::endian::native == std::endian::little) {
                state[i] ^= word; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
            } else {
                state[i] ^= std::byteswap(word); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
            }
        }
        keccak_f1600(state);
        std::memset(buf, 0, rate_bytes);
    }
};


// SHA3-256: rate=136, out=32
inline void sha3_256(const CryptoByte* msg, std::size_t msg_len,
                     CryptoByte out[32]) noexcept // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
{
    Sha3Ctx ctx;
    ctx.init(136, 32); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ctx.update(msg, msg_len);
    ctx.finish(out);
}

// SHA3-384: rate=104, out=48
inline void sha3_384(const CryptoByte* msg, std::size_t msg_len,
                     CryptoByte out[48]) noexcept // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
{
    Sha3Ctx ctx;
    ctx.init(104, 48); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ctx.update(msg, msg_len);
    ctx.finish(out);
}

// SHA3-512: rate=72, out=64
inline void sha3_512(const CryptoByte* msg, std::size_t msg_len,
                     CryptoByte out[64]) noexcept // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
{
    Sha3Ctx ctx;
    ctx.init(72, 64); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ctx.update(msg, msg_len);
    ctx.finish(out);
}

}  // namespace arm_asm::detail
