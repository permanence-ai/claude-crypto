// SPDX-License-Identifier: Apache-2.0

#pragma once

// RSA-OAEP encoding and decoding (RFC 8017, Section 7.1).
//
// Hash function: SHA-384 (hLen = 48 bytes).
// MGF:           MGF1 with SHA-384.
//
// Encoding (OAEP-Encode):
//   EM = 0x00 || maskedSeed || maskedDB
//   DB = lHash || PS || 0x01 || M
//   maskedSeed = seed XOR MGF1(maskedDB, hLen)
//   maskedDB   = DB   XOR MGF1(seed, k - hLen - 1)
//
// Decoding (OAEP-Decode) is constant-time:
//   No secret-dependent branches; uses CT select to hide the error position.
//
// Caller requirements:
//   - out_em must be exactly k bytes (k = modulus_bytes).
//   - seed must be hLen random bytes.

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <array>

#include "defs.hpp"
#include "sha512.hpp"


namespace arm_asm::detail {


constexpr std::size_t oaep_hash_len = 48U;  // SHA-384 output length


// -----------------------------------------------------------------------
// MGF1-SHA384: mask of `out_len` bytes from `seed`.
// RFC 8017 §B.2.1.
// -----------------------------------------------------------------------

inline void mgf1_sha384(
    const CryptoByte* seed, std::size_t seed_len,
    CryptoByte* out, std::size_t out_len) noexcept
{
    std::size_t written = 0;
    for (uint32_t counter = 0; written < out_len; ++counter) {
        // Concatenate seed || I2OSP(counter, 4).
        // Use a stack buffer: seed + 4 bytes for counter.
        // Maximum seed size in OAEP: k bytes (up to 512 for RSA-4096).
        // We allocate generously; the caller controls seed_len.
        constexpr std::size_t max_seed = 512U + 4U;
        std::array<CryptoByte, max_seed> buf{};
        if (seed_len <= max_seed - 4U) {
            std::memcpy(buf.data(), seed, seed_len);
        }
        buf[seed_len + 0U] = static_cast<CryptoByte>((counter >> 24U) & 0xFFU);
        buf[seed_len + 1U] = static_cast<CryptoByte>((counter >> 16U) & 0xFFU);
        buf[seed_len + 2U] = static_cast<CryptoByte>((counter >>  8U) & 0xFFU);
        buf[seed_len + 3U] = static_cast<CryptoByte>( counter         & 0xFFU);

        std::array<CryptoByte, oaep_hash_len> hash{};
        sha384(buf.data(), seed_len + 4U, hash.data());

        const std::size_t take = (out_len - written < oaep_hash_len)
                                  ? (out_len - written) : oaep_hash_len;
        std::memcpy(out + written, hash.data(), take); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        written += take;
    }
}


// -----------------------------------------------------------------------
// OAEP-Encode (RFC 8017 §7.1.1, step 2).
// Writes k bytes to out_em.
// seed must be exactly hLen (48) random bytes.
// Returns false if pt_len > k - 2*hLen - 2.
// -----------------------------------------------------------------------

[[nodiscard]]
inline bool oaep_encode(
    const CryptoByte* pt,    std::size_t pt_len,
    const CryptoByte* label, std::size_t label_len,
    const CryptoByte* seed,          // hLen random bytes
    std::size_t       modulus_bytes, // k
    CryptoByte*       out_em) noexcept
{
    if (modulus_bytes < 2U * oaep_hash_len + 2U) { return false; }
    const std::size_t db_len = modulus_bytes - oaep_hash_len - 1U;  // k - hLen - 1
    const std::size_t max_pt = db_len - oaep_hash_len - 1U;         // k - 2*hLen - 2
    if (pt_len > max_pt) { return false; }

    // DB = lHash || PS || 0x01 || M
    // out_em layout: [0x00][seed: hLen bytes][DB: db_len bytes]
    CryptoByte* out_seed = out_em + 1U; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    CryptoByte* out_db   = out_em + 1U + oaep_hash_len; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)

    out_em[0] = 0x00U;
    std::memcpy(out_seed, seed, oaep_hash_len);

    // lHash at start of DB.
    sha384(label, label_len, out_db);

    // PS (zero bytes) — already zero since we zero-fill below.
    // Ensure PS region is zeroed.
    std::memset(out_db + oaep_hash_len, 0, db_len - oaep_hash_len - 1U - pt_len); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)

    // 0x01 separator.
    out_db[db_len - pt_len - 1U] = 0x01U; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)

    // M.
    std::memcpy(out_db + db_len - pt_len, pt, pt_len); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)

    // maskedDB = DB XOR MGF1(seed, db_len).
    std::array<CryptoByte, 512U> dbmask{};  // max db_len for RSA-4096: 4096/8 - 48 - 1 = 463
    mgf1_sha384(seed, oaep_hash_len, dbmask.data(), db_len);
    for (std::size_t i = 0; i < db_len; ++i) {
        out_db[i] ^= dbmask[i]; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    }

    // maskedSeed = seed XOR MGF1(maskedDB, hLen).
    std::array<CryptoByte, oaep_hash_len> seedmask{};
    mgf1_sha384(out_db, db_len, seedmask.data(), oaep_hash_len);
    for (std::size_t i = 0; i < oaep_hash_len; ++i) {
        out_seed[i] ^= seedmask[i]; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    }

    return true;
}


// -----------------------------------------------------------------------
// OAEP-Decode (RFC 8017 §7.1.2, step 3).
// Constant-time: no secret-dependent branches.
// Returns false on any decoding error.
// -----------------------------------------------------------------------

[[nodiscard]]
inline bool oaep_decode(
    const CryptoByte* em,              // k bytes (raw RSA output)
    std::size_t       modulus_bytes,   // k
    const CryptoByte* label, std::size_t label_len,
    CryptoByte*       pt_out,          // output plaintext
    std::size_t       pt_max,
    std::size_t*      pt_len) noexcept
{
    if (modulus_bytes < 2U * oaep_hash_len + 2U) { return false; }
    const std::size_t db_len = modulus_bytes - oaep_hash_len - 1U;

    // Split EM: Y=em[0], maskedSeed=em[1..hLen], maskedDB=em[1+hLen..k-1].
    const CryptoByte  y          = em[0]; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    const CryptoByte* masked_seed = em + 1U; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    const CryptoByte* masked_db   = em + 1U + oaep_hash_len; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)

    // Recover seed = maskedSeed XOR MGF1(maskedDB, hLen).
    std::array<CryptoByte, oaep_hash_len> seed{};
    std::array<CryptoByte, oaep_hash_len> seed_mask{};
    mgf1_sha384(masked_db, db_len, seed_mask.data(), oaep_hash_len);
    for (std::size_t i = 0; i < oaep_hash_len; ++i) {
        seed[i] = masked_seed[i] ^ seed_mask[i]; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    }

    // Recover DB = maskedDB XOR MGF1(seed, db_len).
    std::array<CryptoByte, 512U> db{};
    std::array<CryptoByte, 512U> db_mask{};
    mgf1_sha384(seed.data(), oaep_hash_len, db_mask.data(), db_len);
    for (std::size_t i = 0; i < db_len; ++i) {
        db[i] = masked_db[i] ^ db_mask[i]; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    }

    // Constant-time checks (accumulate error bits).
    uint8_t err = y;  // Y must be 0x00

    // lHash' = SHA-384(label); compare with DB[0..hLen-1].
    std::array<CryptoByte, oaep_hash_len> lhash{};
    sha384(label, label_len, lhash.data());
    for (std::size_t i = 0; i < oaep_hash_len; ++i) {
        err |= db[i] ^ lhash[i]; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    }

    // Find the 0x01 separator in DB[hLen..db_len-1] (constant-time).
    // We scan forward; once we've seen 0x01, `found` stays 1.
    // All bytes before 0x01 must be 0x00.
    uint8_t found = 0U;
    std::size_t msg_start = db_len;  // index into db[] of first message byte
    for (std::size_t i = oaep_hash_len; i < db_len; ++i) {
        const uint8_t is_one  = static_cast<uint8_t>((db[i] == 0x01U) & (found == 0U)); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
        const uint8_t is_zero = static_cast<uint8_t>( db[i] == 0x00U); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
        // If we haven't found 0x01 yet and this byte is not 0x00 and not 0x01: error.
        err |= static_cast<uint8_t>((found == 0U) & (is_zero == 0U) & (is_one == 0U));
        // Update msg_start in constant-time fashion.
        // When is_one transitions found 0→1, set msg_start = i+1.
        const std::size_t candidate = i + 1U;
        // Use a mask: if is_one, overwrite msg_start.
        const std::size_t mask = static_cast<std::size_t>(-static_cast<std::ptrdiff_t>(is_one));
        msg_start = (candidate & mask) | (msg_start & ~mask);
        found |= is_one;
    }
    err |= static_cast<uint8_t>(found == 0U);  // no 0x01 found

    if (err != 0U) { return false; }

    const std::size_t m_len = db_len - msg_start;
    if (m_len > pt_max) { return false; }

    std::memcpy(pt_out, db.data() + msg_start, m_len); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    *pt_len = m_len;
    return true;
}


}  // namespace arm_asm::detail
