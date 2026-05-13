// SPDX-License-Identifier: Apache-2.0

#pragma once

// ChaCha20-Poly1305 AEAD (RFC 8439) for the IA ASM provider.
//
// See providers/arm_asm/chacha20_poly1305.hpp for the full algorithm description.
// This file is structurally identical but uses ia_asm::detail namespace.

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>

#include "chacha20.hpp"
#include "defs.hpp"
#include "poly1305.hpp"
#include "secure_buffer.hpp"


namespace ia_asm::detail {

constexpr std::size_t chacha20_poly1305_tag_bytes   = 16;
constexpr std::size_t chacha20_poly1305_nonce_bytes  = 12;

// Store a 64-bit value as 8 little-endian bytes.
static inline void store_le64(uint8_t* p, uint64_t v) noexcept {
    if constexpr (std::endian::native == std::endian::big) {
        v = std::byteswap(v);
    }
    std::memcpy(p, &v, 8);
}


// Build the Poly1305 input and compute the tag.
[[gnu::target("sse2")]]
static inline void poly1305_feed( // NOLINT(readability-function-size)
    const CryptoByte* otk, // NOLINT(bugprone-easily-swappable-parameters)
    const CryptoByte* aad, std::size_t aad_len,
    const CryptoByte* ct,  std::size_t ct_len,
    std::span<CryptoByte, poly1305_tag_bytes> tag_out) noexcept
{
    const Poly1305Limbs  r  = clamp_r(std::span<const CryptoByte, poly1305_tag_bytes>{otk, poly1305_tag_bytes});
    const Poly1305Powers pw = Poly1305Powers::build(r);
    Poly1305Limbs h{};

    auto feed_field = [&](const CryptoByte* data, std::size_t len) noexcept {
        std::size_t off = 0;
        while (len - off >= 64) {
            const auto [lo0, hi0] = load_le128(data + off);
            const auto [lo1, hi1] = load_le128(data + off + 16);
            const auto [lo2, hi2] = load_le128(data + off + 32);
            const auto [lo3, hi3] = load_le128(data + off + 48);
            poly1305_process_quad(h, lo0, hi0, lo1, hi1, lo2, hi2, lo3, hi3, pw);
            off += 64;
        }
        if (len - off >= 32) {
            const auto [lo1, hi1] = load_le128(data + off);
            const auto [lo2, hi2] = load_le128(data + off + 16);
            poly1305_process_pair(h, lo1, hi1, lo2, hi2, pw);
            off += 32;
        }
        if (len - off >= 16) {
            const auto [lo, hi] = load_le128(data + off);
            poly1305_add_block(h, lo, hi, 1U);
            poly1305_multiply_precomp(h, pw.p1);
            off += 16;
        }
        if (off < len) {
            std::array<CryptoByte, poly1305_tag_bytes> buf{};
            std::memcpy(buf.data(), data + off, len - off);
            const auto [lo, hi] = load_le128(buf.data());
            poly1305_add_block(h, lo, hi, 1U);
            poly1305_multiply_precomp(h, pw.p1);
        }
    };

    if (aad_len > 0) { feed_field(aad, aad_len); }
    if (ct_len  > 0) { feed_field(ct,  ct_len);  }

    std::array<CryptoByte, poly1305_tag_bytes> len_block{};
    store_le64(len_block.data(),     static_cast<uint64_t>(aad_len));
    store_le64(len_block.data() + 8, static_cast<uint64_t>(ct_len));
    const auto [lo, hi] = load_le128(len_block.data());
    poly1305_add_block(h, lo, hi, 1U);
    poly1305_multiply_precomp(h, pw.p1);

    poly1305_finish(h, std::span<const CryptoByte, poly1305_tag_bytes>{otk + poly1305_tag_bytes, poly1305_tag_bytes}, tag_out);
}


[[gnu::target("sse2")]]
inline void chacha20_poly1305_encrypt( // NOLINT(readability-function-size,readability-function-cognitive-complexity)
    const CryptoByte* key,
    const CryptoByte* nonce, // NOLINT(bugprone-easily-swappable-parameters)
    const CryptoByte* aad,  std::size_t aad_len,
    const CryptoByte* pt,   std::size_t pt_len,
    CryptoByte*       out) noexcept
{
    FixedSecureBuffer<poly1305_key_bytes> otk;
    chacha20_poly1305_key(std::span<const CryptoByte, chacha20_key_size_bytes>{key, chacha20_key_size_bytes},
                          std::span<const CryptoByte, chacha20_poly1305_nonce_bytes>{nonce, chacha20_poly1305_nonce_bytes},
                          std::span<CryptoByte, poly1305_key_bytes>{otk.data(), poly1305_key_bytes});
    chacha20_crypt(std::span<const CryptoByte, chacha20_key_size_bytes>{key, chacha20_key_size_bytes}, 1U,
                   std::span<const CryptoByte, chacha20_poly1305_nonce_bytes>{nonce, chacha20_poly1305_nonce_bytes}, pt, out, pt_len);
    poly1305_feed(otk.data(), aad, aad_len, out, pt_len,
                  std::span<CryptoByte, poly1305_tag_bytes>{out + pt_len, poly1305_tag_bytes});
}


[[gnu::target("sse2")]]
inline bool chacha20_poly1305_decrypt( // NOLINT(readability-function-size,readability-function-cognitive-complexity)
    const CryptoByte* key,
    const CryptoByte* nonce, // NOLINT(bugprone-easily-swappable-parameters)
    const CryptoByte* aad, std::size_t aad_len,
    const CryptoByte* ct,  std::size_t ct_len,
    CryptoByte*       out) noexcept
{
    if (ct_len < chacha20_poly1305_tag_bytes) { return false; }
    const std::size_t pt_len = ct_len - chacha20_poly1305_tag_bytes;

    FixedSecureBuffer<poly1305_key_bytes> otk;
    chacha20_poly1305_key(std::span<const CryptoByte, chacha20_key_size_bytes>{key, chacha20_key_size_bytes},
                          std::span<const CryptoByte, chacha20_poly1305_nonce_bytes>{nonce, chacha20_poly1305_nonce_bytes},
                          std::span<CryptoByte, poly1305_key_bytes>{otk.data(), poly1305_key_bytes});

    std::array<CryptoByte, poly1305_tag_bytes> expected_tag{};
    poly1305_feed(otk.data(), aad, aad_len, ct, pt_len, expected_tag);

    const uint8_t* received_tag = ct + pt_len;
    unsigned int diff = 0;
    for (std::size_t i = 0; i < chacha20_poly1305_tag_bytes; ++i) {
        diff |= static_cast<unsigned int>(expected_tag[i]) ^
                static_cast<unsigned int>(received_tag[i]);
    }

    if (diff != 0U) {
        volatile auto* q = reinterpret_cast<volatile CryptoByte*>(out); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        for (std::size_t i = 0; i < pt_len; ++i) { q[i] = 0; }
        return false;
    }

    chacha20_crypt(std::span<const CryptoByte, chacha20_key_size_bytes>{key, chacha20_key_size_bytes}, 1U,
                   std::span<const CryptoByte, chacha20_poly1305_nonce_bytes>{nonce, chacha20_poly1305_nonce_bytes}, ct, out, pt_len);
    return true;
}

}  // namespace ia_asm::detail
