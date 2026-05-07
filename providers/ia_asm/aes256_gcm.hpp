/*
Copyright Permanence AI, 2026. All rights reserved.

*/

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

#include "aes256.hpp"
#include "defs.hpp"
#include "ghash.hpp"

#ifdef __GNUC__
#pragma GCC target("aes,pclmul,ssse3,sse4.1")
#endif


namespace ia_asm::detail {

constexpr std::size_t aes_gcm_tag_bytes = 16; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
constexpr std::size_t aes_gcm_iv_bytes  = 12; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)


// Increment the low 32 bits of a counter block (big-endian).
static inline void gcm_inc_counter(uint8_t ctr[16]) noexcept { // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    uint32_t lo{};
    std::memcpy(&lo, ctr + 12, 4); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers,cppcoreguidelines-pro-bounds-pointer-arithmetic)
    lo = std::byteswap(std::byteswap(lo) + 1U);
    std::memcpy(ctr + 12, &lo, 4); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers,cppcoreguidelines-pro-bounds-pointer-arithmetic)
}


// CTR encrypt/decrypt (same operation): XOR plaintext/ciphertext with the
// AES-CTR keystream starting at counter block ctr[].
[[gnu::target("aes,ssse3")]]
static inline void gcm_ctr_crypt( // NOLINT(readability-function-size)
    const CryptoByte* in,
    CryptoByte* out,
    std::size_t len,
    uint8_t ctr[16], // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    const Aes256Schedule& sched) noexcept
{
    std::size_t offset = 0;

    // Full blocks.
    while (len - offset >= 16) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        gcm_inc_counter(ctr);
        const __m128i ks = aes256_encrypt_block(_mm_loadu_si128(reinterpret_cast<const __m128i*>(ctr)), sched);
        const __m128i x  = _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(in + offset)), ks); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        _mm_storeu_si128(reinterpret_cast<__m128i*>(out + offset), x); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        offset += 16; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    }

    // Partial final block.
    if (offset < len) {
        gcm_inc_counter(ctr);
        const __m128i ks = aes256_encrypt_block(_mm_loadu_si128(reinterpret_cast<const __m128i*>(ctr)), sched);
        std::array<uint8_t, 16> ks_bytes{}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        _mm_storeu_si128(reinterpret_cast<__m128i*>(ks_bytes.data()), ks);
        for (std::size_t i = 0; offset + i < len; ++i) {
            // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
            out[offset + i] = static_cast<CryptoByte>(in[offset + i] ^ ks_bytes[i]);
        }
    }
}


// Build the GHASH length block: [len(AAD) in bits BE 64] ‖ [len(C) in bits BE 64].
static inline void gcm_length_block(
    uint64_t aad_len,
    uint64_t ct_len,
    uint8_t out[16]) noexcept // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
{
    const uint64_t aad_bits = std::byteswap(aad_len * 8U); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    const uint64_t ct_bits  = std::byteswap(ct_len  * 8U); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    std::memcpy(out,     &aad_bits, 8); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    std::memcpy(out + 8, &ct_bits,  8); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers,cppcoreguidelines-pro-bounds-pointer-arithmetic)
}


// Compute the 16-byte GHASH authentication tag.
[[gnu::target("aes,pclmul,ssse3")]]
static inline void gcm_compute_tag( // NOLINT(readability-function-size)
    const CryptoByte*    aad,
    std::size_t          aad_len,
    const CryptoByte*    ct,
    std::size_t          ct_len,
    const uint8_t        E_J0[16], // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    const Aes256Schedule& sched,
    uint8_t              tag_out[16]) noexcept // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
{
    // H = AES_K(0¹²⁸)
    std::array<uint8_t, 16> H_block{}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    const __m128i H_vec = aes256_encrypt_block(_mm_setzero_si128(), sched);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(H_block.data()), H_vec);

    GhashCtx ghash;
    ghash.init(H_block.data());

    // AAD.
    const std::size_t aad_full_blocks = aad_len / 16; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    for (std::size_t i = 0; i < aad_full_blocks; ++i) {
        ghash.update(aad + (i * 16)); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic,cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    }
    if (aad_len % 16 != 0) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        ghash.update_partial(aad + (aad_full_blocks * 16), aad_len % 16); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic,cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    }

    // Ciphertext.
    const std::size_t ct_full_blocks = ct_len / 16; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    for (std::size_t i = 0; i < ct_full_blocks; ++i) {
        ghash.update(ct + (i * 16)); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic,cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    }
    if (ct_len % 16 != 0) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        ghash.update_partial(ct + (ct_full_blocks * 16), ct_len % 16); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic,cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    }

    // Length block.
    std::array<uint8_t, 16> len_block{}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    gcm_length_block(static_cast<uint64_t>(aad_len),
                     static_cast<uint64_t>(ct_len),
                     len_block.data());
    ghash.update(len_block.data());

    std::array<uint8_t, 16> ghash_out{}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ghash.finish(ghash_out.data());

    for (std::size_t i = 0; i < 16; ++i) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        tag_out[i] = static_cast<uint8_t>(ghash_out[i] ^ E_J0[i]); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    }
}


// AES-256-GCM encrypt.
[[gnu::target("aes,pclmul,ssse3")]]
inline void aes256_gcm_encrypt(
    const CryptoByte* key,
    const CryptoByte* iv,
    const CryptoByte* aad,
    std::size_t       aad_len,
    const CryptoByte* pt,
    std::size_t       pt_len,
    CryptoByte*       out) noexcept
{
    Aes256Schedule sched;
    aes256_key_expand(key, sched);

    std::array<uint8_t, 16> J0{}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    std::memcpy(J0.data(), iv, aes_gcm_iv_bytes);
    J0[15] = 0x01;

    std::array<uint8_t, 16> E_J0{}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    _mm_storeu_si128(reinterpret_cast<__m128i*>(E_J0.data()),
                     aes256_encrypt_block(_mm_loadu_si128(reinterpret_cast<const __m128i*>(J0.data())), sched));

    std::array<uint8_t, 16> ctr{}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    std::memcpy(ctr.data(), J0.data(), 16); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    gcm_ctr_crypt(pt, out, pt_len, ctr.data(), sched);

    gcm_compute_tag(aad, aad_len, out, pt_len, E_J0.data(), sched, out + pt_len); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
}


// AES-256-GCM decrypt.
// ct_len includes the 16-byte tag; out must hold ct_len - 16 bytes.
// Returns true on successful tag verification; if false, out is zeroed.
[[gnu::target("aes,pclmul,ssse3")]]
inline bool aes256_gcm_decrypt(
    const CryptoByte* key,
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
    aes256_key_expand(key, sched);

    std::array<uint8_t, 16> J0{}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    std::memcpy(J0.data(), iv, aes_gcm_iv_bytes);
    J0[15] = 0x01;

    std::array<uint8_t, 16> E_J0{}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    _mm_storeu_si128(reinterpret_cast<__m128i*>(E_J0.data()),
                     aes256_encrypt_block(_mm_loadu_si128(reinterpret_cast<const __m128i*>(J0.data())), sched));

    std::array<uint8_t, 16> expected_tag{}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    gcm_compute_tag(aad, aad_len, ct, pt_len, E_J0.data(), sched, expected_tag.data());

    const uint8_t* received_tag = ct + pt_len; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    unsigned int diff = 0;
    for (std::size_t i = 0; i < aes_gcm_tag_bytes; ++i) {
        diff |= static_cast<unsigned int>(expected_tag[i]) ^
                static_cast<unsigned int>(received_tag[i]); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    }

    if (diff != 0U) {
        volatile auto* p = reinterpret_cast<volatile CryptoByte*>(out); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        for (std::size_t i = 0; i < pt_len; ++i) { p[i] = 0; }
        return false;
    }

    std::array<uint8_t, 16> ctr{}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    std::memcpy(ctr.data(), J0.data(), 16); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    gcm_ctr_crypt(ct, out, pt_len, ctr.data(), sched);
    return true;
}

}  // namespace ia_asm::detail
