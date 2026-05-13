// SPDX-License-Identifier: Apache-2.0

#pragma once

// HMAC using the ARM ASM SHA-256 and SHA-512/384 implementations.
//
// HMAC(K, m) = Hash(opad || Hash(ipad || m))
// where ipad = K' XOR 0x36...  opad = K' XOR 0x5c...
// and K' = K if |K| <= block_size, else Hash(K), zero-padded to block_size.
//
// Block sizes:
//   SHA-256: 64 bytes   output: 32 bytes
//   SHA-384: 128 bytes  output: 48 bytes
//   SHA-512: 128 bytes  output: 64 bytes
//
// Implementation hashes ipad||m and opad||inner incrementally using the raw
// compress functions so no allocation is needed for the concatenated input.

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>

#include "defs.hpp"
#include "secure_buffer.hpp"
#include "sha256.hpp"
#include "sha3.hpp"
#include "sha512.hpp"


namespace arm_asm::detail {

constexpr uint8_t hmac_ipad_byte = 0x36U;
constexpr uint8_t hmac_opad_byte = 0x5cU;

// ---------------------------------------------------------------------------
// Incremental SHA-256 context (feeds blocks one at a time)
// ---------------------------------------------------------------------------
struct Sha256Ctx {
    // NOLINT(misc-non-private-member-variables-in-classes) — plain aggregate; all members intentionally public.
    std::array<uint32_t, 8> state{}; // NOLINT(misc-non-private-member-variables-in-classes)
    ByteArray<sha256_block_bytes> buf{};   // NOLINT(misc-non-private-member-variables-in-classes)
    uint64_t    total_bytes{0}; // NOLINT(misc-non-private-member-variables-in-classes)
    std::size_t buf_used{0};    // NOLINT(misc-non-private-member-variables-in-classes)

    void init() noexcept {
        for (std::size_t i = 0; i < sha256_state_words; ++i) { state[i] = sha256_h0[i]; }
        total_bytes = 0;
        buf_used = 0;
    }

    void update(const uint8_t* data, std::size_t len) noexcept {
        total_bytes += len;
        while (len > 0) {
            const std::size_t space = sha256_block_bytes - buf_used;
            const std::size_t take  = len < space ? len : space;
            std::memcpy(buf.data() + buf_used, data, take);
            buf_used += take;
            data     += take;
            len      -= take;
            if (buf_used == sha256_block_bytes) {
                sha256_compress(state, buf.data());
                buf_used = 0;
            }
        }
    }

    void finish(ByteSpan<sha256_digest_bytes> out) noexcept {
        // Padding: append sha_padding_marker then zeros then 64-bit big-endian bit count.
        alignas(sha256_block_bytes) ByteArray<2 * sha256_block_bytes> pad{};
        std::memcpy(pad.data(), buf.data(), buf_used);
        pad[buf_used] = sha_padding_marker;
        const uint64_t bit_len_be = std::byteswap(total_bytes * bits_per_byte);  // NOLINT(cppcoreguidelines-init-variables)
        if (buf_used < sha256_block_bytes - sizeof(uint64_t)) {
            std::memcpy(pad.data() + (sha256_block_bytes - sizeof(uint64_t)), &bit_len_be, sizeof(uint64_t));
            sha256_compress(state, pad.data());
        } else {
            std::memcpy(pad.data() + ((2U * sha256_block_bytes) - sizeof(uint64_t)), &bit_len_be, sizeof(uint64_t));
            sha256_compress(state, pad.data());
            sha256_compress(state, pad.data() + sha256_block_bytes);
        }
        for (std::size_t i = 0; i < sha256_state_words; ++i) {
            const uint32_t w = std::byteswap(state[i]);  // NOLINT(cppcoreguidelines-init-variables)
            std::memcpy(out.data() + (i * sizeof(uint32_t)), &w, sizeof(uint32_t));
        }
    }
};


// ---------------------------------------------------------------------------
// Incremental SHA-512/384 context (128-byte blocks)
// ---------------------------------------------------------------------------
struct Sha512Ctx {
    std::array<uint64_t, 8>   state{}; // NOLINT(misc-non-private-member-variables-in-classes)
    ByteArray<sha512_block_bytes> buf{};   // NOLINT(misc-non-private-member-variables-in-classes)
    uint64_t    total_bytes{0}; // NOLINT(misc-non-private-member-variables-in-classes)
    std::size_t buf_used{0};    // NOLINT(misc-non-private-member-variables-in-classes)

    void init(std::span<const uint64_t, sha512_state_words> h0) noexcept {
        for (std::size_t i = 0; i < sha512_state_words; ++i) { state[i] = h0[i]; }
        total_bytes = 0;
        buf_used = 0;
    }

    void update(const uint8_t* data, std::size_t len) noexcept {
        total_bytes += len;
        while (len > 0) {
            const std::size_t space = sha512_block_bytes - buf_used;
            const std::size_t take  = len < space ? len : space;
            std::memcpy(buf.data() + buf_used, data, take);
            buf_used += take;
            data     += take;
            len      -= take;
            if (buf_used == sha512_block_bytes) {
                sha512_compress(state, buf.data());
                buf_used = 0;
            }
        }
    }

    void finish(uint8_t* out, std::size_t out_bytes) noexcept {
        alignas(sha512_block_bytes) ByteArray<2 * sha512_block_bytes> pad{};
        std::memcpy(pad.data(), buf.data(), buf_used);
        pad[buf_used] = sha_padding_marker;
        const uint64_t bit_len_be = std::byteswap(total_bytes * bits_per_byte);  // NOLINT(cppcoreguidelines-init-variables)
        if (buf_used < sha512_block_bytes - (2U * sizeof(uint64_t))) {
            std::memcpy(pad.data() + (sha512_block_bytes - sizeof(uint64_t)), &bit_len_be, sizeof(uint64_t));
            sha512_compress(state, pad.data());
        } else {
            std::memcpy(pad.data() + ((2U * sha512_block_bytes) - sizeof(uint64_t)), &bit_len_be, sizeof(uint64_t));
            sha512_compress(state, pad.data());
            sha512_compress(state, pad.data() + sha512_block_bytes);
        }
        for (std::size_t i = 0; i < out_bytes / sizeof(uint64_t); ++i) {
            const uint64_t w = std::byteswap(state[i]);  // NOLINT(cppcoreguidelines-init-variables)
            std::memcpy(out + (i * sizeof(uint64_t)), &w, sizeof(uint64_t));
        }
    }
};


// ---------------------------------------------------------------------------
// HMAC-SHA-256
// ---------------------------------------------------------------------------
// key_len may be 0..any; out must be 32 bytes.
inline void hmac_sha256(const uint8_t* key, std::size_t key_len,
                        const uint8_t* msg, std::size_t msg_len, // NOLINT(bugprone-easily-swappable-parameters)
                        ByteSpan<sha256_digest_bytes> out) noexcept
{
    // Derive K': hash key if > 64 bytes, else use directly.
    FixedSecureBuffer<sha256_block_bytes> kprime;
    if (key_len > sha256_block_bytes) {
        sha256(key, key_len, ByteSpan<sha256_digest_bytes>{kprime.data(), sha256_digest_bytes});
    } else {
        std::memcpy(kprime.data(), key, key_len);
    }

    // Build ipad and opad keys.
    FixedSecureBuffer<sha256_block_bytes> ikey;
    FixedSecureBuffer<sha256_block_bytes> okey;
    for (std::size_t i = 0; i < sha256_block_bytes; ++i) {
        ikey[i] = static_cast<uint8_t>(kprime[i] ^ hmac_ipad_byte);
        okey[i] = static_cast<uint8_t>(kprime[i] ^ hmac_opad_byte);
    }

    // Inner hash: SHA-256(ikey || msg)
    FixedSecureBuffer<sha256_digest_bytes> inner;
    Sha256Ctx ctx;
    ctx.init();
    ctx.update(ikey.data(), sha256_block_bytes);
    ctx.update(msg, msg_len);
    ctx.finish(ByteSpan<sha256_digest_bytes>{inner.data(), sha256_digest_bytes});

    // Outer hash: SHA-256(okey || inner)
    ctx.init();
    ctx.update(okey.data(), sha256_block_bytes);
    ctx.update(inner.data(), sha256_digest_bytes);
    ctx.finish(out);
}


// ---------------------------------------------------------------------------
// HMAC-SHA-512 (and SHA-384 by truncation)
// ---------------------------------------------------------------------------
// key_len may be 0..any; out must be at least out_bytes (48 or 64).
inline void hmac_sha512_impl(std::span<const uint64_t, sha512_state_words> h0, // NOLINT(cppcoreguidelines-avoid-non-const-global-variables,readability-function-size,readability-function-cognitive-complexity)
                              const uint8_t* key, std::size_t key_len,
                              const uint8_t* msg, std::size_t msg_len,
                              uint8_t* out, std::size_t out_bytes) noexcept
{
    // K': hash key if > 128 bytes using the same hash function (FIPS 198-1 §4).
    FixedSecureBuffer<sha512_block_bytes> kprime;
    if (key_len > sha512_block_bytes) {
        Sha512Ctx kctx;
        kctx.init(h0);
        kctx.update(key, key_len);
        kctx.finish(kprime.data(), out_bytes);
    } else {
        std::memcpy(kprime.data(), key, key_len);
    }

    FixedSecureBuffer<sha512_block_bytes> ikey;
    FixedSecureBuffer<sha512_block_bytes> okey;
    for (std::size_t i = 0; i < sha512_block_bytes; ++i) {
        ikey[i] = static_cast<uint8_t>(kprime[i] ^ hmac_ipad_byte);
        okey[i] = static_cast<uint8_t>(kprime[i] ^ hmac_opad_byte);
    }

    // Inner hash.
    FixedSecureBuffer<sha512_digest_bytes> inner;
    Sha512Ctx ctx;
    ctx.init(h0);
    ctx.update(ikey.data(), sha512_block_bytes);
    ctx.update(msg, msg_len);
    ctx.finish(inner.data(), out_bytes);  // only out_bytes of the state words are serialised

    // Outer hash.  Inner digest is out_bytes long; outer input = okey || inner[0..out_bytes).
    ctx.init(h0);
    ctx.update(okey.data(), sha512_block_bytes);
    ctx.update(inner.data(), out_bytes);
    ctx.finish(inner.data(), out_bytes);  // reuse inner as temp
    std::memcpy(out, inner.data(), out_bytes);
}

inline void hmac_sha512(const uint8_t* key, std::size_t key_len,
                        const uint8_t* msg, std::size_t msg_len, // NOLINT(bugprone-easily-swappable-parameters)
                        ByteSpan<sha512_digest_bytes> out) noexcept
{
    hmac_sha512_impl(sha512_h0, key, key_len, msg, msg_len, out.data(), sha512_digest_bytes);
}

inline void hmac_sha384(const uint8_t* key, std::size_t key_len,
                        const uint8_t* msg, std::size_t msg_len, // NOLINT(bugprone-easily-swappable-parameters)
                        ByteSpan<sha384_digest_bytes> out) noexcept
{
    hmac_sha512_impl(sha384_h0, key, key_len, msg, msg_len, out.data(), sha384_digest_bytes);
}


// ---------------------------------------------------------------------------
// HMAC-SHA3 (SHA3-256, SHA3-384, SHA3-512)
//
// SHA-3 HMAC uses the FIPS 202 / FIPS 198-1 construction with the SHA-3 rate
// as the block size (not 64 or 128 bytes as in SHA-2):
//   SHA3-256: block=136 bytes, out=32 bytes
//   SHA3-384: block=104 bytes, out=48 bytes
//   SHA3-512: block= 72 bytes, out=64 bytes
// ---------------------------------------------------------------------------
inline void hmac_sha3_impl(std::size_t rate, std::size_t out_bytes, // NOLINT(bugprone-easily-swappable-parameters,readability-function-size,readability-function-cognitive-complexity)
                            const uint8_t* key, std::size_t key_len,
                            const uint8_t* msg, std::size_t msg_len,
                            uint8_t* out) noexcept
{
    // K': hash key if > rate, else use directly.
    // sha3_max_rate_bytes = SHA3-256 rate = 136 bytes (max across all variants).
    FixedSecureBuffer<sha3_max_rate_bytes> kprime;
    if (key_len > rate) {
        Sha3Ctx kctx;
        kctx.init(rate, out_bytes);
        kctx.update(key, key_len);
        kctx.finish(kprime.data());
    } else {
        std::memcpy(kprime.data(), key, key_len);
    }

    FixedSecureBuffer<sha3_max_rate_bytes> ikey;
    FixedSecureBuffer<sha3_max_rate_bytes> okey;
    for (std::size_t i = 0; i < rate; ++i) {
        ikey[i] = static_cast<uint8_t>(kprime[i] ^ hmac_ipad_byte);
        okey[i] = static_cast<uint8_t>(kprime[i] ^ hmac_opad_byte);
    }

    // Inner hash: SHA3(ikey || msg)
    FixedSecureBuffer<sha512_digest_bytes> inner;
    Sha3Ctx ctx;
    ctx.init(rate, out_bytes);
    ctx.update(ikey.data(), rate);
    ctx.update(msg, msg_len);
    ctx.finish(inner.data());

    // Outer hash: SHA3(okey || inner[0..out_bytes))
    ctx.init(rate, out_bytes);
    ctx.update(okey.data(), rate);
    ctx.update(inner.data(), out_bytes);
    ctx.finish(out);
}

inline void hmac_sha3_256(const uint8_t* key, std::size_t key_len,
                           const uint8_t* msg, std::size_t msg_len, // NOLINT(bugprone-easily-swappable-parameters)
                           ByteSpan<sha3_256_digest_bytes> out) noexcept
{
    hmac_sha3_impl(sha3_max_rate_bytes, sha3_256_digest_bytes, key, key_len, msg, msg_len, out.data());
}

inline void hmac_sha3_384(const uint8_t* key, std::size_t key_len,
                           const uint8_t* msg, std::size_t msg_len, // NOLINT(bugprone-easily-swappable-parameters)
                           ByteSpan<sha3_384_digest_bytes> out) noexcept
{
    hmac_sha3_impl(sha3_384_rate_bytes_v, sha3_384_digest_bytes, key, key_len, msg, msg_len, out.data());
}

inline void hmac_sha3_512(const uint8_t* key, std::size_t key_len,
                           const uint8_t* msg, std::size_t msg_len, // NOLINT(bugprone-easily-swappable-parameters)
                           ByteSpan<sha3_512_digest_bytes> out) noexcept
{
    hmac_sha3_impl(sha3_512_rate_bytes_v, sha3_512_digest_bytes, key, key_len, msg, msg_len, out.data());
}

}  // namespace arm_asm::detail
