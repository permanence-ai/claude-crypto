// SPDX-License-Identifier: Apache-2.0

#pragma once

// AES-256-GCM authenticated encryption/decryption using AES-NI + PCLMULQDQ.
//
// See providers/arm_asm/aes256_gcm.hpp for the full algorithm description.
// This file is structurally identical but uses ia_asm::detail namespace and
// Intel SSE/AES-NI intrinsics.

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <immintrin.h>
#include <span>

#include "aes256.hpp"
#include "defs.hpp"
#include "ghash.hpp"


namespace ia_asm::detail {

constexpr std::size_t aes_gcm_tag_bytes = 16;
constexpr std::size_t aes_gcm_iv_bytes  = 12;


// Increment the low 32 bits of a counter block (big-endian).
static inline void gcm_inc_counter(ByteSpan<aes_gcm_tag_bytes> ctr) noexcept {
    uint32_t lo{};
    std::memcpy(&lo, ctr.data() + 12, 4);
    lo = std::byteswap(std::byteswap(lo) + 1U);
    std::memcpy(ctr.data() + 12, &lo, 4);
}


// CTR encrypt/decrypt (same operation): XOR plaintext/ciphertext with the
// AES-CTR keystream starting at counter block ctr[].
[[gnu::target("aes,ssse3")]]
static inline void gcm_ctr_crypt( // NOLINT(readability-function-size)
    const CryptoByte* in,  // NOLINT(bugprone-easily-swappable-parameters)
    CryptoByte* out,       // NOLINT(bugprone-easily-swappable-parameters,readability-non-const-parameter)
    std::size_t len,       // NOLINT(bugprone-easily-swappable-parameters)
    ByteSpan<aes_gcm_tag_bytes> ctr,
    const Aes256Schedule& sched) noexcept
{
    std::size_t offset = 0;

    // Full blocks.
    while (len - offset >= 16) {
        gcm_inc_counter(ctr);
        const __m128i ks = aes256_encrypt_block(_mm_loadu_si128(reinterpret_cast<const __m128i*>(ctr.data())), sched); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        const __m128i x  = _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(in + offset)), ks); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        _mm_storeu_si128(reinterpret_cast<__m128i*>(out + offset), x); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        offset += 16;
    }

    // Partial final block.
    if (offset < len) {
        gcm_inc_counter(ctr);
        const __m128i ks = aes256_encrypt_block(_mm_loadu_si128(reinterpret_cast<const __m128i*>(ctr.data())), sched); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        ByteArray<aes_gcm_tag_bytes> ks_bytes{};
        _mm_storeu_si128(reinterpret_cast<__m128i*>(ks_bytes.data()), ks); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        for (std::size_t i = 0; offset + i < len; ++i) {

            out[offset + i] = static_cast<CryptoByte>(in[offset + i] ^ ks_bytes[i]);
        }
    }
}


// Build the GHASH length block: [len(AAD) in bits BE 64] ‖ [len(C) in bits BE 64].
static inline void gcm_length_block(
    uint64_t aad_len, // NOLINT(bugprone-easily-swappable-parameters)
    uint64_t ct_len,
    ByteSpan<aes_gcm_tag_bytes> out) noexcept
{
    const uint64_t aad_bits = std::byteswap(aad_len * 8U);
    const uint64_t ct_bits  = std::byteswap(ct_len  * 8U);
    std::memcpy(out.data(),     &aad_bits, 8);
    std::memcpy(out.data() + 8, &ct_bits,  8);
}


// Compute the 16-byte GHASH authentication tag.
[[gnu::target("aes,pclmul,ssse3")]]
static inline void gcm_compute_tag( // NOLINT(readability-function-size)
    const CryptoByte*    aad, // NOLINT(bugprone-easily-swappable-parameters)
    std::size_t          aad_len,
    const CryptoByte*    ct,
    std::size_t          ct_len, // NOLINT(bugprone-easily-swappable-parameters)
    CByteSpan<aes_gcm_tag_bytes> E_J0,
    const Aes256Schedule& sched,
    ByteSpan<aes_gcm_tag_bytes> tag_out) noexcept
{
    // H = AES_K(0¹²⁸)
    ByteArray<aes_gcm_tag_bytes> H_block{};
    const __m128i H_vec = aes256_encrypt_block(_mm_setzero_si128(), sched);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(H_block.data()), H_vec); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)

    GhashCtx ghash;
    ghash.init(H_block.data());

    // AAD.
    const std::size_t aad_full_blocks = aad_len / 16;
    for (std::size_t i = 0; i < aad_full_blocks; ++i) {
        ghash.update(aad + (i * 16));
    }
    if (aad_len % 16 != 0) {
        ghash.update_partial(aad + (aad_full_blocks * 16), aad_len % 16);
    }

    // Ciphertext.
    const std::size_t ct_full_blocks = ct_len / 16;
    for (std::size_t i = 0; i < ct_full_blocks; ++i) {
        ghash.update(ct + (i * 16));
    }
    if (ct_len % 16 != 0) {
        ghash.update_partial(ct + (ct_full_blocks * 16), ct_len % 16);
    }

    // Length block.
    ByteArray<aes_gcm_tag_bytes> len_block{};
    gcm_length_block(static_cast<uint64_t>(aad_len),
                     static_cast<uint64_t>(ct_len),
                     len_block);
    ghash.update(len_block.data());

    ByteArray<aes_gcm_tag_bytes> ghash_out{};
    ghash.finish(ghash_out.data());

    for (std::size_t i = 0; i < aes_gcm_tag_bytes; ++i) {
        tag_out[i] = static_cast<CryptoByte>(ghash_out[i] ^ E_J0[i]);
    }
}


// AES-256-GCM encrypt.
[[gnu::target("aes,pclmul,ssse3")]]
inline void aes256_gcm_encrypt( // NOLINT(readability-function-size,readability-function-cognitive-complexity)
    const CryptoByte* key, // NOLINT(bugprone-easily-swappable-parameters)
    const CryptoByte* iv,
    const CryptoByte* aad,
    std::size_t       aad_len,
    const CryptoByte* pt,
    std::size_t       pt_len,
    CryptoByte*       out) noexcept
{
    Aes256Schedule sched;
    aes256_key_expand(CByteSpan<aes256_key_size_bytes>{key, aes256_key_size_bytes}, sched);

    ByteArray<aes_gcm_tag_bytes> J0{};
    std::memcpy(J0.data(), iv, aes_gcm_iv_bytes);
    J0[15] = 0x01;

    ByteArray<aes_gcm_tag_bytes> E_J0{};
    _mm_storeu_si128(reinterpret_cast<__m128i*>(E_J0.data()), // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
                     aes256_encrypt_block(_mm_loadu_si128(reinterpret_cast<const __m128i*>(J0.data())), sched)); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)

    ByteArray<aes_gcm_tag_bytes> ctr{};
    std::memcpy(ctr.data(), J0.data(), aes_gcm_tag_bytes);
    gcm_ctr_crypt(pt, out, pt_len, ctr, sched);

    gcm_compute_tag(aad, aad_len, out, pt_len, E_J0, sched, ByteSpan<aes_gcm_tag_bytes>{out + pt_len, aes_gcm_tag_bytes});
}


// AES-256-GCM decrypt.
// ct_len includes the 16-byte tag; out must hold ct_len - 16 bytes.
// Returns true on successful tag verification; if false, out is zeroed.
[[gnu::target("aes,pclmul,ssse3")]]
inline bool aes256_gcm_decrypt( // NOLINT(readability-function-size,readability-function-cognitive-complexity)
    const CryptoByte* key, // NOLINT(bugprone-easily-swappable-parameters)
    const CryptoByte* iv,
    const CryptoByte* aad,
    std::size_t       aad_len,
    const CryptoByte* ct,
    std::size_t       ct_len,
    CryptoByte*       out) noexcept
{
    if (ct_len < aes_gcm_tag_bytes) { return false; }
    const std::size_t pt_len = ct_len - aes_gcm_tag_bytes;

    Aes256Schedule sched;
    aes256_key_expand(CByteSpan<aes256_key_size_bytes>{key, aes256_key_size_bytes}, sched);

    ByteArray<aes_gcm_tag_bytes> J0{};
    std::memcpy(J0.data(), iv, aes_gcm_iv_bytes);
    J0[15] = 0x01;

    ByteArray<aes_gcm_tag_bytes> E_J0{};
    _mm_storeu_si128(reinterpret_cast<__m128i*>(E_J0.data()), // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
                     aes256_encrypt_block(_mm_loadu_si128(reinterpret_cast<const __m128i*>(J0.data())), sched)); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)

    ByteArray<aes_gcm_tag_bytes> expected_tag{};
    gcm_compute_tag(aad, aad_len, ct, pt_len, E_J0, sched, expected_tag);

    const CryptoByte* received_tag = ct + pt_len;
    unsigned int diff = 0;
    for (std::size_t i = 0; i < aes_gcm_tag_bytes; ++i) {
        diff |= static_cast<unsigned int>(expected_tag[i]) ^
                static_cast<unsigned int>(received_tag[i]);
    }

    if (diff != 0U) {
        volatile auto* p = reinterpret_cast<volatile CryptoByte*>(out); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        for (std::size_t i = 0; i < pt_len; ++i) { p[i] = 0; }
        return false;
    }

    ByteArray<aes_gcm_tag_bytes> ctr{};
    std::memcpy(ctr.data(), J0.data(), aes_gcm_tag_bytes);
    gcm_ctr_crypt(ct, out, pt_len, ctr, sched);
    return true;
}

}  // namespace ia_asm::detail
