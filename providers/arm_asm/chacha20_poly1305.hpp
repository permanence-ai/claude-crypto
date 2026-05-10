// SPDX-License-Identifier: Apache-2.0

#pragma once

// ChaCha20-Poly1305 AEAD (RFC 8439).
//
// Construction:
//   1. Generate one-time key: otk = ChaCha20(key, counter=0, nonce)[0..31]
//   2. Encrypt plaintext:     ct  = ChaCha20(key, counter=1, nonce) XOR pt
//   3. Build Poly1305 message: aad_padded ‖ ct_padded ‖ len64(aad) ‖ len64(ct)
//      where each padded field is the data followed by zero bytes to the next
//      16-byte boundary.
//   4. Compute MAC:           tag = Poly1305(otk, poly_msg)
//
// Decrypt verifies the tag with a constant-time compare before decrypting.
// On tag failure the output buffer is zeroized.
//
// Key: 32 bytes.
// Nonce: 12 bytes (96-bit, RFC 8439 §2.3).
// Tag: 16 bytes, appended to ciphertext in encrypt output.

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "chacha20.hpp"
#include "defs.hpp"
#include "poly1305.hpp"
#include "secure_buffer.hpp"


namespace arm_asm::detail {

constexpr std::size_t chacha20_poly1305_tag_bytes  = 16;
constexpr std::size_t chacha20_poly1305_nonce_bytes = 12;

// Store a 64-bit value as 8 little-endian bytes.
static inline void store_le64(uint8_t* p, uint64_t v) noexcept {
    if constexpr (std::endian::native == std::endian::big) {
        v = std::byteswap(v);
    }
    std::memcpy(p, &v, 8);
}

// Build the Poly1305 input: aad_padded ‖ ct_padded ‖ len64(aad) ‖ len64(ct).
// Feeds data into Poly1305 block-by-block without a large stack allocation.
// Uses 4-block parallel processing via precomputed r^1..r^4 powers.
[[gnu::target("neon")]]
static inline void poly1305_feed(const uint8_t* otk,
                                  const uint8_t* aad, std::size_t aad_len,
                                  const uint8_t* ct,  std::size_t ct_len,
                                  std::span<CryptoByte, poly1305_tag_bytes> tag_out) noexcept
{


    // We re-implement the MAC computation inline here to avoid building a huge
    // intermediate buffer.  We walk through the fields in order:
    //   aad (padded to 16), ct (padded to 16), length block (16 bytes).
    const Poly1305Limbs  r  = clamp_r(std::span<const CryptoByte, poly1305_tag_bytes>{otk, poly1305_tag_bytes});
    const Poly1305Powers pw = Poly1305Powers::build(r);
    Poly1305Limbs h{};

    // Helper: feed one field (data, len) followed by zero-padding to 16 bytes.
    // In the AEAD construction every Poly1305 block is a full 16-byte block
    // (top bit = 2^128), even the partial ones — the zero-padding is part of
    // the field format, not a Poly1305 partial-block marker.
    auto feed_field = [&](const uint8_t* data, std::size_t len) noexcept {
        std::size_t off = 0;
        // Process groups of four full 16-byte blocks with r⁴.
        while (len - off >= 64) {

            const auto [lo0, hi0] = load_le128(data + off);

            const auto [lo1, hi1] = load_le128(data + off + 16);

            const auto [lo2, hi2] = load_le128(data + off + 32);

            const auto [lo3, hi3] = load_le128(data + off + 48);
            poly1305_process_quad(h, lo0, hi0, lo1, hi1, lo2, hi2, lo3, hi3, pw);
            off += 64;
        }
        // Remaining pair of full blocks.
        if (len - off >= 32) {

            const auto [lo1, hi1] = load_le128(data + off);

            const auto [lo2, hi2] = load_le128(data + off + 16);
            poly1305_process_pair(h, lo1, hi1, lo2, hi2, pw);
            off += 32;
        }
        // Remaining single full block.
        if (len - off >= 16) {

            const auto [lo, hi] = load_le128(data + off);
            poly1305_add_block(h, lo, hi, 1U);
            poly1305_multiply_precomp(h, pw.p1);
            off += 16;
        }
        // Partial block: zero-pad to 16 bytes; top=1 (full block with zero fill).
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

    // Length block: [len(aad) LE 64-bit] ‖ [len(ct) LE 64-bit].
    std::array<CryptoByte, poly1305_tag_bytes> len_block{};
    store_le64(len_block.data(),     static_cast<uint64_t>(aad_len));
    store_le64(len_block.data() + 8, static_cast<uint64_t>(ct_len));
    const auto [lo, hi] = load_le128(len_block.data());
    poly1305_add_block(h, lo, hi, 1U);
    poly1305_multiply_precomp(h, pw.p1);

    poly1305_finish(h, std::span<const CryptoByte, poly1305_tag_bytes>{otk + poly1305_tag_bytes, poly1305_tag_bytes}, tag_out);
}


// ChaCha20-Poly1305 encrypt.
//   key, nonce: 32 and 12 bytes respectively.
//   out: must hold pt_len + 16 bytes.
[[gnu::target("neon")]]
inline void chacha20_poly1305_encrypt( // NOLINT(readability-function-size,readability-function-cognitive-complexity)
    const CryptoByte* key,
    const CryptoByte* nonce,
    const CryptoByte* aad,  std::size_t aad_len,
    const CryptoByte* pt,   std::size_t pt_len,
    CryptoByte*       out) noexcept
{
    // Generate one-time key.
    FixedSecureBuffer<poly1305_key_bytes> otk;
    chacha20_poly1305_key(std::span<const CryptoByte, chacha20_key_size_bytes>{key, chacha20_key_size_bytes},
                          std::span<const CryptoByte, chacha20_poly1305_nonce_bytes>{nonce, chacha20_poly1305_nonce_bytes},
                          std::span<CryptoByte, poly1305_key_bytes>{otk.data(), poly1305_key_bytes});

    // Encrypt plaintext (counter starts at 1).
    chacha20_crypt(std::span<const CryptoByte, chacha20_key_size_bytes>{key, chacha20_key_size_bytes}, 1U,
                   std::span<const CryptoByte, chacha20_poly1305_nonce_bytes>{nonce, chacha20_poly1305_nonce_bytes}, pt, out, pt_len);

    // Compute and append Poly1305 tag over aad ‖ ct.

    poly1305_feed(otk.data(), aad, aad_len, out, pt_len,
                  std::span<CryptoByte, poly1305_tag_bytes>{out + pt_len, poly1305_tag_bytes});
}


// ChaCha20-Poly1305 decrypt.
//   ct_len includes the 16-byte tag.
//   Returns true on successful tag verification; on failure out is zeroized.
[[gnu::target("neon")]]
inline bool chacha20_poly1305_decrypt( // NOLINT(readability-function-size,readability-function-cognitive-complexity)
    const CryptoByte* key,
    const CryptoByte* nonce,
    const CryptoByte* aad, std::size_t aad_len,
    const CryptoByte* ct,  std::size_t ct_len,
    CryptoByte*       out) noexcept
{
    if (ct_len < chacha20_poly1305_tag_bytes) { return false; }
    const std::size_t pt_len = ct_len - chacha20_poly1305_tag_bytes;

    // Generate one-time key.
    FixedSecureBuffer<poly1305_key_bytes> otk;
    chacha20_poly1305_key(std::span<const CryptoByte, chacha20_key_size_bytes>{key, chacha20_key_size_bytes},
                          std::span<const CryptoByte, chacha20_poly1305_nonce_bytes>{nonce, chacha20_poly1305_nonce_bytes},
                          std::span<CryptoByte, poly1305_key_bytes>{otk.data(), poly1305_key_bytes});

    // Compute expected tag from the received ciphertext.
    std::array<CryptoByte, poly1305_tag_bytes> expected_tag{};
    poly1305_feed(otk.data(), aad, aad_len, ct, pt_len, expected_tag);

    // Constant-time compare.

    const uint8_t* received_tag = ct + pt_len;
    unsigned int diff = 0;
    for (std::size_t i = 0; i < chacha20_poly1305_tag_bytes; ++i) {

        diff |= static_cast<unsigned int>(expected_tag[i]) ^
                static_cast<unsigned int>(received_tag[i]);
    }

    if (diff != 0U) {
        // Zeroize output before returning authentication failure.
        volatile auto* q = reinterpret_cast<volatile CryptoByte*>(out); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        for (std::size_t i = 0; i < pt_len; ++i) { q[i] = 0; }
        return false;
    }

    // Decrypt (counter=1).
    chacha20_crypt(std::span<const CryptoByte, chacha20_key_size_bytes>{key, chacha20_key_size_bytes}, 1U,
                   std::span<const CryptoByte, chacha20_poly1305_nonce_bytes>{nonce, chacha20_poly1305_nonce_bytes}, ct, out, pt_len);
    return true;
}

}  // namespace arm_asm::detail
