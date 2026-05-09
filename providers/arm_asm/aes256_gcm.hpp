// SPDX-License-Identifier: Apache-2.0

#pragma once

// AES-256-GCM authenticated encryption/decryption.
//
// Follows NIST SP 800-38D.  Key sizes: 32-byte key, 12-byte IV (standard GCM
// convention where the 96-bit nonce is used directly as the initial counter).
//
// Counter block (J0) formation for 96-bit IV:
//   J0 = IV ‖ 0x00000001  (big-endian counter, starts at 1)
//
// CTR keystream:
//   E(K, inc(J)) for each 16-byte plaintext block, where inc() increments the
//   low 32 bits in big-endian order.
//
// Authentication tag:
//   GHASH_H(AAD_padded ‖ C_padded ‖ len(A)‖len(C)) XOR E(K, J0)
//   We pass nullptr/0 for AAD since the high-level API does not use it.
//
// Output layout (encrypt): ciphertext ‖ 16-byte tag
// Input layout  (decrypt): ciphertext ‖ 16-byte tag; tag verified with
//   constant-time compare before returning plaintext.

#include <arm_neon.h>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "aes256.hpp"
#include "defs.hpp"
#include "ghash.hpp"


namespace arm_asm::detail {

constexpr std::size_t aes_gcm_tag_bytes = 16;
constexpr std::size_t aes_gcm_iv_bytes  = 12;


// Increment the low 32 bits of a counter block (big-endian).
static inline void gcm_inc_counter(uint8_t ctr[16]) noexcept {
    // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    uint32_t lo{};
    std::memcpy(&lo, ctr + 12, 4);
    lo = std::byteswap(std::byteswap(lo) + 1U);
    std::memcpy(ctr + 12, &lo, 4);
}


// CTR encrypt/decrypt (same operation): XOR plaintext/ciphertext with the
// AES-CTR keystream starting at counter block ctr[].
// ctr[] is updated to the counter value after the last full block used.
[[gnu::target("aes,neon")]]
static inline void gcm_ctr_crypt(
    const CryptoByte* in,
    CryptoByte* out,
    std::size_t len,
    uint8_t ctr[16],
    const Aes256Schedule& sched) noexcept
{
    std::size_t offset = 0;

    // Full blocks.
    while (len - offset >= 16) {
        gcm_inc_counter(ctr);
        const uint8x16_t ks = aes256_encrypt_block(vld1q_u8(ctr), sched);
        const uint8x16_t x  = veorq_u8(vld1q_u8(in + offset), ks);
        vst1q_u8(out + offset, x);
        offset += 16;
    }

    // Partial final block.
    if (offset < len) {
        gcm_inc_counter(ctr);
        const uint8x16_t ks = aes256_encrypt_block(vld1q_u8(ctr), sched);
        std::array<uint8_t, 16> ks_bytes{};
        vst1q_u8(ks_bytes.data(), ks);
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
    uint8_t out[16]) noexcept
{
    // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    const uint64_t aad_bits = std::byteswap(aad_len * 8U);
    const uint64_t ct_bits  = std::byteswap(ct_len  * 8U);
    std::memcpy(out,     &aad_bits, 8);
    std::memcpy(out + 8, &ct_bits,  8);
}


// Compute the 16-byte GHASH authentication tag.
//   H       = AES_K(0)
//   E_J0    = AES_K(J0)
//   tag     = GHASH_H(aad_padded ‖ ct_padded ‖ len_block) XOR E_J0
[[gnu::target("aes,neon")]]
static inline void gcm_compute_tag( // NOLINT(readability-function-size,readability-function-cognitive-complexity)
    const CryptoByte*    aad,
    std::size_t          aad_len,
    const CryptoByte*    ct,
    std::size_t          ct_len,
    const uint8_t        E_J0[16],
    const Aes256Schedule& sched,
    uint8_t              tag_out[16]) noexcept
{
    // H = AES_K(0¹²⁸)
    std::array<uint8_t, 16> H_block{};
    const uint8x16_t H_vec = aes256_encrypt_block(vdupq_n_u8(0), sched);
    vst1q_u8(H_block.data(), H_vec);

    GhashCtx ghash;
    ghash.init(H_block.data());

    // AAD (padded to block boundary).
    const std::size_t aad_full_blocks = aad_len / 16;
    for (std::size_t i = 0; i < aad_full_blocks; ++i) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        ghash.update(aad + (i * 16));
    }
    if (aad_len % 16 != 0) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        ghash.update_partial(aad + (aad_full_blocks * 16), aad_len % 16);
    }

    // Ciphertext (padded to block boundary).
    const std::size_t ct_full_blocks = ct_len / 16;
    for (std::size_t i = 0; i < ct_full_blocks; ++i) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        ghash.update(ct + (i * 16));
    }
    if (ct_len % 16 != 0) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        ghash.update_partial(ct + (ct_full_blocks * 16), ct_len % 16);
    }

    // Length block.
    std::array<uint8_t, 16> len_block{};
    gcm_length_block(static_cast<uint64_t>(aad_len),
                     static_cast<uint64_t>(ct_len),
                     len_block.data());
    ghash.update(len_block.data());

    std::array<uint8_t, 16> ghash_out{};
    ghash.finish(ghash_out.data());

    // tag = GHASH XOR E_J0
    for (std::size_t i = 0; i < 16; ++i) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
        tag_out[i] = static_cast<uint8_t>(ghash_out[i] ^ E_J0[i]);
    }
}


// AES-256-GCM encrypt.
//   key      : 32 bytes
//   iv       : 12 bytes
//   aad      : additional authenticated data (may be nullptr if aad_len == 0)
//   pt       : plaintext
//   pt_len   : plaintext length
//   out      : must hold pt_len + 16 bytes (ciphertext + tag)
[[gnu::target("aes,neon")]]
inline void aes256_gcm_encrypt( // NOLINT(readability-function-size,readability-function-cognitive-complexity)
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

    // J0 = IV ‖ 0x00000001
    std::array<uint8_t, 16> J0{};
    std::memcpy(J0.data(), iv, aes_gcm_iv_bytes);
    J0[15] = 0x01;

    // E(K, J0) — used to finalise the tag.
    std::array<uint8_t, 16> E_J0{};
    vst1q_u8(E_J0.data(), aes256_encrypt_block(vld1q_u8(J0.data()), sched));

    // CTR encrypt starting from counter J0 (gcm_ctr_crypt increments before use).
    std::array<uint8_t, 16> ctr{};
    std::memcpy(ctr.data(), J0.data(), 16);
    gcm_ctr_crypt(pt, out, pt_len, ctr.data(), sched);

    // Compute tag over AAD and ciphertext.
    gcm_compute_tag(aad, aad_len, out, pt_len, E_J0.data(), sched, out + pt_len); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
}


// AES-256-GCM decrypt.
//   ct_len includes the 16-byte tag; out must hold ct_len - 16 bytes.
//   Returns true on successful tag verification; if false, out is zeroed.
[[gnu::target("aes,neon")]]
inline bool aes256_gcm_decrypt( // NOLINT(readability-function-size,readability-function-cognitive-complexity)
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

    std::array<uint8_t, 16> J0{};
    std::memcpy(J0.data(), iv, aes_gcm_iv_bytes);
    J0[15] = 0x01;

    std::array<uint8_t, 16> E_J0{};
    vst1q_u8(E_J0.data(), aes256_encrypt_block(vld1q_u8(J0.data()), sched));

    // Verify the tag before decrypting (constant-time compare).
    std::array<uint8_t, 16> expected_tag{};
    gcm_compute_tag(aad, aad_len, ct, pt_len, E_J0.data(), sched, expected_tag.data());

    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    const uint8_t* received_tag = ct + pt_len;
    unsigned int diff = 0;
    for (std::size_t i = 0; i < aes_gcm_tag_bytes; ++i) {
        diff |= static_cast<unsigned int>(expected_tag[i]) ^
                static_cast<unsigned int>(received_tag[i]); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    }

    if (diff != 0U) {
        // Zeroize output before returning authentication failure.
        volatile auto* p = reinterpret_cast<volatile CryptoByte*>(out); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        for (std::size_t i = 0; i < pt_len; ++i) { p[i] = 0; }
        return false;
    }

    std::array<uint8_t, 16> ctr{};
    std::memcpy(ctr.data(), J0.data(), 16);
    gcm_ctr_crypt(ct, out, pt_len, ctr.data(), sched);
    return true;
}

}  // namespace arm_asm::detail
