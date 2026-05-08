// SPDX-License-Identifier: Apache-2.0

#pragma once

// RSA-PSS encoding and verification (RFC 8017, Section 9.1).
//
// Hash function: SHA-384 (hLen = 48 bytes).
// MGF:           MGF1 with SHA-384.
// Salt length:   hLen = 48 bytes (matches PSA default PSA_ALG_RSA_PSS).
//
// Encoding (EMSA-PSS-Encode, RFC 8017 §9.1.1):
//   EM = maskedDB || H || 0xBC
//   DB = PS || 0x01 || salt
//   H  = Hash(0x00^8 || mHash || salt)
//   maskedDB = DB XOR MGF1(H, emLen - hLen - 1)
//   Top bits of maskedDB[0] are zeroed to emBits = modBits - 1.
//
// Verification (EMSA-PSS-Verify, RFC 8017 §9.1.2) is constant-time.
//
// Salt length equals hLen.  emBits = modBits - 1.

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <array>

#include "defs.hpp"
#include "sha512.hpp"
#include "rsa_oaep.hpp"   // reuse mgf1_sha384 and oaep_hash_len


namespace arm_asm::detail {


// -----------------------------------------------------------------------
// PSS-Encode (EMSA-PSS-Encode, RFC 8017 §9.1.1).
// Writes emLen bytes to out_em.
// salt must be exactly hLen (48) random bytes.
// modulus_bits: the bit length of the RSA modulus.
// Returns false if the message hash is too long for the EM.
// -----------------------------------------------------------------------

[[nodiscard]]
inline bool pss_encode(
    const CryptoByte* msg,     std::size_t msg_len,
    const CryptoByte* salt,              // hLen random bytes
    std::size_t       modulus_bits,
    CryptoByte*       out_em) noexcept
{
    const std::size_t em_bits = modulus_bits - 1U;
    const std::size_t em_len  = (em_bits + 7U) / 8U;

    // PSS requires emLen >= hLen + sLen + 2.
    if (em_len < (2U * oaep_hash_len) + 2U) { return false; }

    const std::size_t db_len = em_len - oaep_hash_len - 1U;  // emLen - hLen - 1

    // mHash = Hash(M).
    std::array<CryptoByte, oaep_hash_len> m_hash{};
    sha384(msg, msg_len, m_hash.data());

    // H = Hash(0x00^8 || mHash || salt).
    std::array<CryptoByte, 8U + oaep_hash_len + oaep_hash_len> h_input{};
    std::memset(h_input.data(), 0, 8U);
    std::memcpy(h_input.data() + 8U,                m_hash.data(), oaep_hash_len);
    std::memcpy(h_input.data() + 8U + oaep_hash_len, salt,          oaep_hash_len);
    std::array<CryptoByte, oaep_hash_len> h{};
    sha384(h_input.data(), h_input.size(), h.data());

    // DB = PS || 0x01 || salt.
    // PS = emLen - sLen - hLen - 2 zero bytes.
    const std::size_t ps_len = em_len - oaep_hash_len - oaep_hash_len - 2U;
    std::memset(out_em, 0, ps_len); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    out_em[ps_len] = 0x01U; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    std::memcpy(out_em + ps_len + 1U, salt, oaep_hash_len); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)

    // maskedDB = DB XOR MGF1(H, db_len).
    std::array<CryptoByte, 512U> db_mask{};
    mgf1_sha384(h.data(), oaep_hash_len, db_mask.data(), db_len);
    for (std::size_t i = 0; i < db_len; ++i) {
        out_em[i] ^= db_mask[i]; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    }

    // Zero the top (8*emLen - emBits) bits of maskedDB[0].
    const std::size_t top_bits = (8U * em_len) - em_bits;
    if (top_bits > 0U) {
        out_em[0] &= static_cast<CryptoByte>(0xFFU >> top_bits); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    }

    // Append H and 0xBC.
    CryptoByte* out_h  = out_em + db_len; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    CryptoByte* out_bc = out_em + db_len + oaep_hash_len; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    std::memcpy(out_h, h.data(), oaep_hash_len);
    *out_bc = 0xBCU;

    return true;
}


// -----------------------------------------------------------------------
// PSS-Verify (EMSA-PSS-Verify, RFC 8017 §9.1.2).
// Constant-time: no secret-dependent branches.
// em must be emLen bytes (emLen = ceil((modBits-1)/8)).
// Returns true iff the signature is valid.
// -----------------------------------------------------------------------

[[nodiscard]]
inline bool pss_verify(
    const CryptoByte* msg,     std::size_t msg_len,
    const CryptoByte* em,
    std::size_t       modulus_bits) noexcept
{
    const std::size_t em_bits = modulus_bits - 1U;
    const std::size_t em_len  = (em_bits + 7U) / 8U;

    if (em_len < (2U * oaep_hash_len) + 2U) { return false; }

    const std::size_t db_len = em_len - oaep_hash_len - 1U;

    // Check trailing 0xBC.
    if (em[em_len - 1U] != 0xBCU) { return false; } // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)

    const CryptoByte* masked_db = em; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    const CryptoByte* h         = em + db_len; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)

    // Check top bits of maskedDB[0] are zero.
    const std::size_t top_bits = (8U * em_len) - em_bits;
    const uint8_t top_mask = static_cast<uint8_t>(0xFFU << (8U - top_bits));
    if ((masked_db[0] & top_mask) != 0U) { return false; } // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)

    // DB = maskedDB XOR MGF1(H, db_len).
    std::array<CryptoByte, 512U> db{};
    std::array<CryptoByte, 512U> db_mask{};
    mgf1_sha384(h, oaep_hash_len, db_mask.data(), db_len);
    for (std::size_t i = 0; i < db_len; ++i) {
        db[i] = masked_db[i] ^ db_mask[i]; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    }

    // Zero the top bits of DB[0].
    if (top_bits > 0U) {
        db[0] &= static_cast<uint8_t>(0xFFU >> top_bits); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    }

    // Constant-time checks (accumulate error bits).
    uint8_t err = 0U;

    // PS must be all zeros; DB[ps_len] must be 0x01.
    const std::size_t ps_len = em_len - oaep_hash_len - oaep_hash_len - 2U;
    for (std::size_t i = 0; i < ps_len; ++i) {
        err |= db[i]; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    }
    err |= static_cast<uint8_t>(db[ps_len] ^ 0x01U); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)

    if (err != 0U) { return false; }

    // Extract salt = DB[ps_len+1 .. ps_len+hLen].
    const CryptoByte* salt = db.data() + ps_len + 1U; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)

    // mHash = Hash(M).
    std::array<CryptoByte, oaep_hash_len> m_hash{};
    sha384(msg, msg_len, m_hash.data());

    // H' = Hash(0x00^8 || mHash || salt).
    std::array<CryptoByte, 8U + oaep_hash_len + oaep_hash_len> h_input{};
    std::memset(h_input.data(), 0, 8U);
    std::memcpy(h_input.data() + 8U,                m_hash.data(), oaep_hash_len);
    std::memcpy(h_input.data() + 8U + oaep_hash_len, salt,          oaep_hash_len);
    std::array<CryptoByte, oaep_hash_len> h_prime{};
    sha384(h_input.data(), h_input.size(), h_prime.data());

    // Constant-time compare H' with H.
    uint8_t diff = 0U;
    for (std::size_t i = 0; i < oaep_hash_len; ++i) {
        diff |= static_cast<uint8_t>(h[i] ^ h_prime[i]); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    }
    return diff == 0U;
}


}  // namespace arm_asm::detail
