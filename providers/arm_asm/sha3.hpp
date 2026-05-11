// SPDX-License-Identifier: Apache-2.0

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

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "defs.hpp"
#include "keccak.hpp"


namespace arm_asm::detail {

// Number of lanes the sponge XORs per round = rate_bytes / 8.
// SHA3-256: 17, SHA3-384: 13, SHA3-512: 9.

// Maximum sponge rate across all SHA-3 variants (SHA3-256 rate = 136 bytes).
constexpr std::size_t sha3_max_rate_bytes = 136;

// Incremental SHA-3 context.  Holds the 1600-bit Keccak state, a partial block
// buffer sized to the maximum rate (SHA3-256, 136 bytes), and state metadata.
struct Sha3Ctx {
    // NOLINT(misc-non-private-member-variables-in-classes) — plain aggregate.
    std::array<uint64_t, 25> state{}; // NOLINT(misc-non-private-member-variables-in-classes)
    std::array<uint8_t, sha3_max_rate_bytes> buf{}; // NOLINT(misc-non-private-member-variables-in-classes)
    std::size_t rate_bytes{0}; // NOLINT(misc-non-private-member-variables-in-classes)
    std::size_t out_bytes{0};  // NOLINT(misc-non-private-member-variables-in-classes)
    std::size_t buf_used{0};   // NOLINT(misc-non-private-member-variables-in-classes)

    void init(std::size_t rate, std::size_t out) noexcept {
        state.fill(0);
        buf.fill(0);
        rate_bytes = rate;
        out_bytes  = out;
        buf_used   = 0;
    }

    void update(const uint8_t* data, std::size_t len) noexcept {
        while (len > 0) {
            const std::size_t space = rate_bytes - buf_used;
            const std::size_t take  = len < space ? len : space;
            std::memcpy(buf.data() + buf_used, data, take);
            buf_used += take;
            data     += take;
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
        std::memset(buf.data() + buf_used, 0, rate_bytes - buf_used);
        buf[buf_used]        = 0x06U;
        buf[rate_bytes - 1] ^= 0x80U;
        absorb_block();

        // Squeeze: output lanes are already in little-endian byte order on LE
        // hardware (Apple Silicon is LE), so write directly.
        for (std::size_t i = 0; i < out_bytes; ++i) {

            out[i] = static_cast<uint8_t>(state[i / 8] >> ((i % 8) * 8));
        }
    }

private:
    void absorb_block() noexcept {
        // XOR the rate lanes into the state (little-endian byte order).
        const std::size_t lanes = rate_bytes / 8;
        for (std::size_t i = 0; i < lanes; ++i) {
            uint64_t word = 0;
            std::memcpy(&word, buf.data() + (i * 8), 8);
            if constexpr (std::endian::native == std::endian::little) {
                state[i] ^= word;
            } else {
                state[i] ^= std::byteswap(word);
            }
        }
        keccak_f1600(state);
        std::memset(buf.data(), 0, rate_bytes);
    }
};


// SHA3-256: rate=136, out=32
inline void sha3_256(const CryptoByte* msg, std::size_t msg_len,
                     ByteSpan<sha256_digest_bytes> out) noexcept
{
    Sha3Ctx ctx;
    ctx.init(136, sha256_digest_bytes);
    ctx.update(msg, msg_len);
    ctx.finish(out.data());
}

// SHA3-384: rate=104, out=48
inline void sha3_384(const CryptoByte* msg, std::size_t msg_len,
                     ByteSpan<sha384_digest_bytes> out) noexcept
{
    Sha3Ctx ctx;
    ctx.init(104, sha384_digest_bytes);
    ctx.update(msg, msg_len);
    ctx.finish(out.data());
}

// SHA3-512: rate=72, out=64
inline void sha3_512(const CryptoByte* msg, std::size_t msg_len,
                     ByteSpan<sha512_digest_bytes> out) noexcept
{
    Sha3Ctx ctx;
    ctx.init(72, sha512_digest_bytes);
    ctx.update(msg, msg_len);
    ctx.finish(out.data());
}

}  // namespace arm_asm::detail
