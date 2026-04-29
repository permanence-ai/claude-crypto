/*
Copyright Permanence AI, 2026. All rights reserved.

*/

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

#include "defs.hpp"
#include "sha256.hpp"
#include "sha3.hpp"
#include "sha512.hpp"


namespace arm_asm::detail {

// ---------------------------------------------------------------------------
// Incremental SHA-256 context (feeds blocks one at a time)
// ---------------------------------------------------------------------------
struct Sha256Ctx {
    // NOLINT(misc-non-private-member-variables-in-classes) — plain aggregate; all members intentionally public.
    uint32_t    state[8]; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays,misc-non-private-member-variables-in-classes)
    uint8_t     buf[64];  // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays,misc-non-private-member-variables-in-classes,cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    uint64_t    total_bytes; // NOLINT(misc-non-private-member-variables-in-classes)
    std::size_t buf_used;    // NOLINT(misc-non-private-member-variables-in-classes)

    void init() noexcept {
        for (std::size_t i = 0; i < 8; ++i) { state[i] = sha256_h0[i]; }
        total_bytes = 0;
        buf_used = 0;
    }

    void update(const uint8_t* data, std::size_t len) noexcept {
        total_bytes += len;
        while (len > 0) {
            const std::size_t space = 64 - buf_used;
            const std::size_t take  = len < space ? len : space;
            std::memcpy(buf + buf_used, data, take);
            buf_used += take;
            data     += take;
            len      -= take;
            if (buf_used == 64) {
                sha256_compress(state, buf);
                buf_used = 0;
            }
        }
    }

    void finish(uint8_t out[32]) noexcept {
        // Padding: append 0x80 then zeros then 64-bit big-endian bit count.
        alignas(64) uint8_t pad[128]{};
        std::memcpy(pad, buf, buf_used);
        pad[buf_used] = 0x80U;
        const uint64_t bit_len_be = std::byteswap(total_bytes * 8U);
        if (buf_used < 56) {
            std::memcpy(pad + 56, &bit_len_be, 8);
            sha256_compress(state, pad);
        } else {
            std::memcpy(pad + 120, &bit_len_be, 8);
            sha256_compress(state, pad);
            sha256_compress(state, pad + 64);
        }
        for (std::size_t i = 0; i < 8; ++i) {
            const uint32_t w = std::byteswap(state[i]);
            std::memcpy(out + i * 4, &w, 4);
        }
    }
};


// ---------------------------------------------------------------------------
// Incremental SHA-512/384 context (128-byte blocks)
// ---------------------------------------------------------------------------
struct Sha512Ctx {
    uint64_t    state[8];  // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays,misc-non-private-member-variables-in-classes,cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    uint8_t     buf[128];  // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays,misc-non-private-member-variables-in-classes,cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    uint64_t    total_bytes; // NOLINT(misc-non-private-member-variables-in-classes)
    std::size_t buf_used;    // NOLINT(misc-non-private-member-variables-in-classes)

    void init(const uint64_t h0[8]) noexcept {
        for (std::size_t i = 0; i < 8; ++i) { state[i] = h0[i]; }
        total_bytes = 0;
        buf_used = 0;
    }

    void update(const uint8_t* data, std::size_t len) noexcept {
        total_bytes += len;
        while (len > 0) {
            const std::size_t space = 128 - buf_used;
            const std::size_t take  = len < space ? len : space;
            std::memcpy(buf + buf_used, data, take);
            buf_used += take;
            data     += take;
            len      -= take;
            if (buf_used == 128) {
                sha512_compress(state, buf);
                buf_used = 0;
            }
        }
    }

    void finish(uint8_t out[64], std::size_t out_bytes) noexcept {
        alignas(128) uint8_t pad[256]{};
        std::memcpy(pad, buf, buf_used);
        pad[buf_used] = 0x80U;
        const uint64_t bit_len_be = std::byteswap(total_bytes * 8U);
        if (buf_used < 112) {
            std::memcpy(pad + 120, &bit_len_be, 8);
            sha512_compress(state, pad);
        } else {
            std::memcpy(pad + 248, &bit_len_be, 8);
            sha512_compress(state, pad);
            sha512_compress(state, pad + 128);
        }
        for (std::size_t i = 0; i < out_bytes / 8; ++i) {
            const uint64_t w = std::byteswap(state[i]);
            std::memcpy(out + i * 8, &w, 8);
        }
    }
};


// ---------------------------------------------------------------------------
// HMAC-SHA-256
// ---------------------------------------------------------------------------
// key_len may be 0..any; out must be 32 bytes.
inline void hmac_sha256(const uint8_t* key, std::size_t key_len,
                        const uint8_t* msg, std::size_t msg_len,
                        uint8_t out[32]) noexcept
{
    // Derive K': hash key if > 64 bytes, else use directly.
    uint8_t kprime[64]{};
    if (key_len > 64) {
        sha256(key, key_len, kprime);
    } else {
        std::memcpy(kprime, key, key_len);
    }

    // Build ipad and opad keys.
    uint8_t ikey[64], okey[64];
    for (std::size_t i = 0; i < 64; ++i) {
        ikey[i] = static_cast<uint8_t>(kprime[i] ^ 0x36U);
        okey[i] = static_cast<uint8_t>(kprime[i] ^ 0x5cU);
    }

    // Inner hash: SHA-256(ikey || msg)
    uint8_t inner[32];
    Sha256Ctx ctx;
    ctx.init();
    ctx.update(ikey, 64);
    ctx.update(msg, msg_len);
    ctx.finish(inner);

    // Outer hash: SHA-256(okey || inner)
    ctx.init();
    ctx.update(okey, 64);
    ctx.update(inner, 32);
    ctx.finish(out);
}


// ---------------------------------------------------------------------------
// HMAC-SHA-512 (and SHA-384 by truncation)
// ---------------------------------------------------------------------------
// key_len may be 0..any; out must be at least out_bytes (48 or 64).
inline void hmac_sha512_impl(const uint64_t h0[8],
                              const uint8_t* key, std::size_t key_len,
                              const uint8_t* msg, std::size_t msg_len,
                              uint8_t* out, std::size_t out_bytes) noexcept
{
    // K': hash key if > 128 bytes using the same hash function (FIPS 198-1 §4).
    uint8_t kprime[128]{};
    if (key_len > 128) {
        Sha512Ctx kctx;
        kctx.init(h0);
        kctx.update(key, key_len);
        kctx.finish(kprime, out_bytes);
    } else {
        std::memcpy(kprime, key, key_len);
    }

    uint8_t ikey[128], okey[128];
    for (std::size_t i = 0; i < 128; ++i) {
        ikey[i] = static_cast<uint8_t>(kprime[i] ^ 0x36U);
        okey[i] = static_cast<uint8_t>(kprime[i] ^ 0x5cU);
    }

    // Inner hash.
    uint8_t inner[64];
    Sha512Ctx ctx;
    ctx.init(h0);
    ctx.update(ikey, 128);
    ctx.update(msg, msg_len);
    ctx.finish(inner, out_bytes);  // only out_bytes of the state words are serialised

    // Outer hash.  Inner digest is out_bytes long; outer input = okey || inner[0..out_bytes).
    ctx.init(h0);
    ctx.update(okey, 128);
    ctx.update(inner, out_bytes);
    ctx.finish(reinterpret_cast<uint8_t*>(inner), out_bytes);  // reuse inner as temp
    std::memcpy(out, inner, out_bytes);
}

inline void hmac_sha512(const uint8_t* key, std::size_t key_len,
                        const uint8_t* msg, std::size_t msg_len,
                        uint8_t out[64]) noexcept
{
    hmac_sha512_impl(sha512_h0, key, key_len, msg, msg_len, out, 64);
}

inline void hmac_sha384(const uint8_t* key, std::size_t key_len,
                        const uint8_t* msg, std::size_t msg_len,
                        uint8_t out[48]) noexcept // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
{
    hmac_sha512_impl(sha384_h0, key, key_len, msg, msg_len, out, 48);
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
inline void hmac_sha3_impl(std::size_t rate, std::size_t out_bytes,
                            const uint8_t* key, std::size_t key_len,
                            const uint8_t* msg, std::size_t msg_len,
                            uint8_t* out) noexcept
{
    // K': hash key if > rate, else use directly.
    uint8_t kprime[136]{}; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays,cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    if (key_len > rate) {
        Sha3Ctx kctx;
        kctx.init(rate, out_bytes);
        kctx.update(key, key_len);
        kctx.finish(kprime);
    } else {
        std::memcpy(kprime, key, key_len);
    }

    uint8_t ikey[136], okey[136]; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays,cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    for (std::size_t i = 0; i < rate; ++i) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
        ikey[i] = static_cast<uint8_t>(kprime[i] ^ 0x36U);
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
        okey[i] = static_cast<uint8_t>(kprime[i] ^ 0x5cU);
    }

    // Inner hash: SHA3(ikey || msg)
    uint8_t inner[64]{}; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays,cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    Sha3Ctx ctx;
    ctx.init(rate, out_bytes);
    ctx.update(ikey, rate);
    ctx.update(msg, msg_len);
    ctx.finish(inner);

    // Outer hash: SHA3(okey || inner[0..out_bytes))
    ctx.init(rate, out_bytes);
    ctx.update(okey, rate);
    ctx.update(inner, out_bytes);
    ctx.finish(out);
}

inline void hmac_sha3_256(const uint8_t* key, std::size_t key_len,
                           const uint8_t* msg, std::size_t msg_len,
                           uint8_t out[32]) noexcept // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
{
    hmac_sha3_impl(136, 32, key, key_len, msg, msg_len, out); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
}

inline void hmac_sha3_384(const uint8_t* key, std::size_t key_len,
                           const uint8_t* msg, std::size_t msg_len,
                           uint8_t out[48]) noexcept // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
{
    hmac_sha3_impl(104, 48, key, key_len, msg, msg_len, out); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
}

inline void hmac_sha3_512(const uint8_t* key, std::size_t key_len,
                           const uint8_t* msg, std::size_t msg_len,
                           uint8_t out[64]) noexcept // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
{
    hmac_sha3_impl(72, 64, key, key_len, msg, msg_len, out); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
}

}  // namespace arm_asm::detail
