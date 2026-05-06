// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Permanence AI

#pragma once

// ECDSA sign and verify for P-256, P-384, and P-521.
//
// Signing: deterministic (RFC 6979) using HMAC-SHA-256 (P-256), HMAC-SHA-384 (P-384),
//          or HMAC-SHA-512 (P-521).
// Output format: r‖s big-endian raw (PSA raw ECDSA format):
//   P-256: 64 bytes (32+32)
//   P-384: 96 bytes (48+48)
//   P-521: 132 bytes (66+66)
//
// Verification: standard EC point computation + r comparison.

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "hmac.hpp"
#include "p256_point.hpp"
#include "p384_point.hpp"
#include "p521_point.hpp"
#include "secure_buffer.hpp"


namespace arm_asm::detail {


// -----------------------------------------------------------------------
// RFC 6979 deterministic nonce generation.
// -----------------------------------------------------------------------

// Generate a deterministic per-message scalar k in [1, n-1] using RFC 6979.
// Uses HMAC-SHA-256 (P-256), HMAC-SHA-384 (P-384), or HMAC-SHA-512 (P-521).
// scalar_be: private key scalar (big-endian, qlen bytes)
// hash_be:   message hash (big-endian, hlen bytes, ≤ qlen)
// k_out:     output k (big-endian, qlen bytes)
// qlen:      byte length of curve order (32 for P-256, 48 for P-384, 66 for P-521)

static inline void rfc6979_generate_k( // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    const uint8_t* scalar_be, std::size_t qlen,
    const uint8_t* hash_be,   std::size_t hlen,
    const uint64_t* n_limbs,  std::size_t n_limb_count,
    uint8_t* k_out) noexcept
{
    // Step a: hash is h1 = H(m), already provided.
    // Step b: V = 0x01 * qlen
    FixedSecureBuffer<66> V{};  // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    for (std::size_t i = 0; i < qlen; ++i) { V[i] = 0x01U; }

    // Step c: K = 0x00 * qlen
    FixedSecureBuffer<66> K{};  // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    // K is already zero-initialized by FixedSecureBuffer.

    // Combine message for HMAC: V || 0x00 || x || h1
    // Max: qlen(66) + 1 + qlen(66) + hlen(64) = 197
    FixedSecureBuffer<66 + 1 + 66 + 64> msg_buf{};  // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)

    // Step d: K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1))
    // Step e: V = HMAC_K(V)
    // Step f: K = HMAC_K(V || 0x01 || int2octets(x) || bits2octets(h1))
    // Step g: V = HMAC_K(V)

    for (int round = 0; round < 2; ++round) {
        std::size_t off = 0;
        std::memcpy(msg_buf.data() + off, V.data(), qlen); off += qlen;
        msg_buf[off] = static_cast<uint8_t>(round);  // 0x00 then 0x01
        ++off;
        std::memcpy(msg_buf.data() + off, scalar_be, qlen); off += qlen;
        // bits2octets(h1): hash truncated/expanded to qlen bytes
        if (hlen >= qlen) {
            std::memcpy(msg_buf.data() + off, hash_be, qlen);
        } else {
            std::memset(msg_buf.data() + off, 0, qlen - hlen);
            std::memcpy(msg_buf.data() + off + (qlen - hlen), hash_be, hlen); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        }
        off += qlen;

        if (qlen == 32) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
            hmac_sha256(K.data(), qlen, msg_buf.data(), off, K.data());
            hmac_sha256(K.data(), qlen, V.data(), qlen, V.data());
        } else if (qlen == 48) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
            hmac_sha384(K.data(), qlen, msg_buf.data(), off, K.data());
            hmac_sha384(K.data(), qlen, V.data(), qlen, V.data());
        } else {
            hmac_sha512(K.data(), qlen, msg_buf.data(), off, K.data());
            hmac_sha512(K.data(), qlen, V.data(), qlen, V.data());
        }
    }

    // Step h: generate candidate T until valid k found.
    // In practice the first candidate is almost always valid.
    for (int attempt = 0; attempt < 100; ++attempt) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        if (qlen == 32) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
            hmac_sha256(K.data(), qlen, V.data(), qlen, V.data());
        } else if (qlen == 48) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
            hmac_sha384(K.data(), qlen, V.data(), qlen, V.data());
        } else {
            hmac_sha512(K.data(), qlen, V.data(), qlen, V.data());
        }
        // V is now candidate T (with qlen bytes)
        std::memcpy(k_out, V.data(), qlen);

        // Check k is in [1, n-1]: not zero and < n.
        bool is_zero = true;
        for (std::size_t i = 0; i < qlen; ++i) {
            if (k_out[i] != 0U) { is_zero = false; break; }
        }
        if (is_zero) { goto update_kv; }  // NOLINT(cppcoreguidelines-avoid-goto,hicpp-avoid-goto)

        // Check k < n: compare big-endian k_out with n_limbs (LE).
        {
            // Convert k_out BE to LE limbs for comparison.
            const std::size_t n_bytes = n_limb_count * 8;
            bool k_lt_n = false;
            // Compare from MSB.
            for (int j = static_cast<int>(n_limb_count) - 1; j >= 0; --j) {
                uint64_t k_limb = 0;
                for (int b = 0; b < 8; ++b) {
                    const std::size_t byte_pos = n_bytes - 1U - ((static_cast<std::size_t>(j) * 8U) + static_cast<std::size_t>(b)); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
                    if (byte_pos < qlen) {
                        k_limb |= static_cast<uint64_t>(k_out[byte_pos]) << (static_cast<unsigned>(b) * 8U); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
                    }
                }
                if (k_limb < n_limbs[j]) { k_lt_n = true; break; }
                if (k_limb > n_limbs[j]) { k_lt_n = false; break; }
            }
            if (k_lt_n) { return; }
        }

update_kv:
        // K = HMAC_K(V || 0x00)
        {
            FixedSecureBuffer<66 + 1> tmp{};  // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
            std::memcpy(tmp.data(), V.data(), qlen);
            tmp[qlen] = 0x00U;
            if (qlen == 32) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
                hmac_sha256(K.data(), qlen, tmp.data(), qlen + 1, K.data());
                hmac_sha256(K.data(), qlen, V.data(), qlen, V.data());
            } else if (qlen == 48) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
                hmac_sha384(K.data(), qlen, tmp.data(), qlen + 1, K.data());
                hmac_sha384(K.data(), qlen, V.data(), qlen, V.data());
            } else {
                hmac_sha512(K.data(), qlen, tmp.data(), qlen + 1, K.data());
                hmac_sha512(K.data(), qlen, V.data(), qlen, V.data());
            }
        }
    }
}


// -----------------------------------------------------------------------
// P-256 ECDSA.
// -----------------------------------------------------------------------

// Sign: private_scalar_be[32], msg_hash[32] → sig_out[64] (r‖s BE).
static inline bool p256_ecdsa_sign( // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    const uint8_t private_scalar_be[32],
    const uint8_t msg_hash[32],
    uint8_t sig_out[64]) noexcept
{
    using Fe = Fe256;
    using Point = P256Point;
    constexpr std::size_t qlen = 32;

    // Hash of message: e = H(m) reduced mod n.
    const Fe e = p256_scalar_from_bytes32(msg_hash);
    const Fe d = p256_scalar_from_bytes32(private_scalar_be);
    if (p256_scalar_is_zero(d)) { return false; }

    // Generate deterministic k via RFC 6979.
    FixedSecureBuffer<qlen> k_buf{};
    rfc6979_generate_k(private_scalar_be, qlen, msg_hash, qlen,
                       p256_n, 4, k_buf.data()); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)

    const Fe k = p256_scalar_from_bytes32(k_buf.data());
    if (p256_scalar_is_zero(k)) { return false; }

    // R = k·G, r = R.x mod n.
    const Point R = p256_to_affine(p256_scalar_mul_base(k_buf.data()));
    if (p256_point_is_identity(R)) { return false; }

    // r = R.x mod n (R.x is in [0, p-1]; n < p so just subtract n once if needed).
    uint8_t rx_bytes[qlen] = {};
    fe256_to_bytes(R.X, rx_bytes);
    const Fe r = p256_scalar_from_bytes32(rx_bytes);
    if (p256_scalar_is_zero(r)) { return false; }

    // s = k^{-1} * (e + r*d) mod n.
    const Fe rd   = p256_scalar_mul_mod_n(r, d);
    const Fe eprd = p256_scalar_add(e, rd);
    const Fe kinv = p256_scalar_invert(k);
    const Fe s    = p256_scalar_mul_mod_n(kinv, eprd);
    if (p256_scalar_is_zero(s)) { return false; }

    // Output r‖s big-endian.
    fe256_to_bytes(r, sig_out);
    fe256_to_bytes(s, sig_out + qlen); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    return true;
}

// Verify: public_key_uncompressed[65] (0x04||x||y), msg_hash[32], sig[64] (r‖s BE).
static inline bool p256_ecdsa_verify( // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    const uint8_t public_key_uncompressed[65],
    const uint8_t msg_hash[32],
    const uint8_t sig[64]) noexcept
{
    using Fe = Fe256;
    using Point = P256Point;
    constexpr std::size_t qlen = 32;

    if (public_key_uncompressed[0] != 0x04U) { return false; }

    Fe r{}, s{};
    if (!p256_scalar_sig_decode(sig,          r)) { return false; } // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    if (!p256_scalar_sig_decode(sig + qlen,   s)) { return false; } // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)

    const Fe e = p256_scalar_from_bytes32(msg_hash);
    const Fe w = p256_scalar_invert(s);

    const Fe u1 = p256_scalar_mul_mod_n(e, w);
    const Fe u2 = p256_scalar_mul_mod_n(r, w);

    // Encode u1, u2 as scalars.
    uint8_t u1b[qlen] = {};
    uint8_t u2b[qlen] = {};
    fe256_to_bytes(u1, u1b);
    fe256_to_bytes(u2, u2b);

    // Compute u1·G + u2·Q.
    const Fe Qx = fe256_from_bytes(public_key_uncompressed + 1);  // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    const Fe Qy = fe256_from_bytes(public_key_uncompressed + 33); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic,cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    if (!p256_validate_public_point(Qx, Qy)) { return false; }
    const Point Q{.X = Qx, .Y = Qy, .Z = fe256_one};

    const Point X = p256_to_affine(p256_point_add(
        p256_scalar_mul_base(u1b),
        p256_scalar_mul(Q, u2b)));

    if (p256_point_is_identity(X)) { return false; }

    // Compare X.x mod n with r.
    uint8_t xx_bytes[qlen] = {};
    fe256_to_bytes(X.X, xx_bytes);
    const Fe xr = p256_scalar_from_bytes32(xx_bytes);
    return fe256_equal(xr, r);
}


// -----------------------------------------------------------------------
// P-384 ECDSA.
// -----------------------------------------------------------------------

static inline bool p384_ecdsa_sign( // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    const uint8_t private_scalar_be[48],
    const uint8_t msg_hash[48],
    uint8_t sig_out[96]) noexcept // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
{
    using Fe = Fe384;
    using Point = P384Point;
    constexpr std::size_t qlen = 48; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)

    const Fe e = p384_scalar_from_bytes48(msg_hash);
    const Fe d = p384_scalar_from_bytes48(private_scalar_be);
    if (p384_scalar_is_zero(d)) { return false; }

    FixedSecureBuffer<qlen> k_buf{};
    rfc6979_generate_k(private_scalar_be, qlen, msg_hash, qlen,
                       p384_n, 6, k_buf.data()); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)

    const Fe k = p384_scalar_from_bytes48(k_buf.data());
    if (p384_scalar_is_zero(k)) { return false; }

    const Point R = p384_to_affine(p384_scalar_mul_base(k_buf.data()));
    if (p384_point_is_identity(R)) { return false; }

    uint8_t rx_bytes[qlen] = {};
    fe384_to_bytes(R.X, rx_bytes);
    const Fe r = p384_scalar_from_bytes48(rx_bytes);
    if (p384_scalar_is_zero(r)) { return false; }

    const Fe rd   = p384_scalar_mul_mod_n(r, d);
    const Fe eprd = p384_scalar_add(e, rd);
    const Fe kinv = p384_scalar_invert(k);
    const Fe s    = p384_scalar_mul_mod_n(kinv, eprd);
    if (p384_scalar_is_zero(s)) { return false; }

    fe384_to_bytes(r, sig_out);
    fe384_to_bytes(s, sig_out + qlen); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    return true;
}

static inline bool p384_ecdsa_verify( // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    const uint8_t public_key_uncompressed[97],
    const uint8_t msg_hash[48],
    const uint8_t sig[96]) noexcept // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
{
    using Fe = Fe384;
    using Point = P384Point;
    constexpr std::size_t qlen = 48; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)

    if (public_key_uncompressed[0] != 0x04U) { return false; }

    Fe r{}, s{};
    if (!p384_scalar_sig_decode(sig,          r)) { return false; } // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    if (!p384_scalar_sig_decode(sig + qlen,   s)) { return false; } // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)

    const Fe e = p384_scalar_from_bytes48(msg_hash);
    const Fe w = p384_scalar_invert(s);

    const Fe u1 = p384_scalar_mul_mod_n(e, w);
    const Fe u2 = p384_scalar_mul_mod_n(r, w);

    uint8_t u1b[qlen] = {};
    uint8_t u2b[qlen] = {};
    fe384_to_bytes(u1, u1b);
    fe384_to_bytes(u2, u2b);

    const Fe Qx = fe384_from_bytes(public_key_uncompressed + 1);   // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    const Fe Qy = fe384_from_bytes(public_key_uncompressed + 49);  // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic,cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    if (!p384_validate_public_point(Qx, Qy)) { return false; }
    const Point Q{.X = Qx, .Y = Qy, .Z = fe384_one};

    const Point X = p384_to_affine(p384_point_add(
        p384_scalar_mul_base(u1b),
        p384_scalar_mul(Q, u2b)));

    if (p384_point_is_identity(X)) { return false; }

    uint8_t xx_bytes[qlen] = {};
    fe384_to_bytes(X.X, xx_bytes);
    const Fe xr = p384_scalar_from_bytes48(xx_bytes);
    return fe384_equal(xr, r);
}


// -----------------------------------------------------------------------
// P-521 ECDSA.
// -----------------------------------------------------------------------

static inline bool p521_ecdsa_sign( // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    const uint8_t private_scalar_be[66], // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    const uint8_t msg_hash[64],          // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    uint8_t sig_out[132]) noexcept       // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
{
    using Fe = Fe521;
    using Point = P521Point;
    constexpr std::size_t qlen = 66; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    constexpr std::size_t hlen = 64; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)

    const Fe e = p521_scalar_from_bytes66_hash(msg_hash, hlen);
    const Fe d = p521_scalar_from_bytes66(private_scalar_be);
    if (p521_scalar_is_zero(d)) { return false; }

    FixedSecureBuffer<qlen> k_buf{};
    rfc6979_generate_k(private_scalar_be, qlen, msg_hash, hlen,
                       p521_n, 9, k_buf.data()); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)

    const Fe k = p521_scalar_from_bytes66(k_buf.data());
    if (p521_scalar_is_zero(k)) { return false; }

    const Point R = p521_to_affine(p521_scalar_mul_base(k_buf.data()));
    if (p521_point_is_identity(R)) { return false; }

    uint8_t rx_bytes[qlen] = {};
    fe521_to_bytes(R.X, rx_bytes);
    const Fe r = p521_scalar_from_bytes66(rx_bytes);
    if (p521_scalar_is_zero(r)) { return false; }

    const Fe rd   = p521_scalar_mul_mod_n(r, d);
    const Fe eprd = p521_scalar_add(e, rd);
    const Fe kinv = p521_scalar_invert(k);
    const Fe s    = p521_scalar_mul_mod_n(kinv, eprd);
    if (p521_scalar_is_zero(s)) { return false; }

    fe521_to_bytes(r, sig_out);
    fe521_to_bytes(s, sig_out + qlen); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    return true;
}

static inline bool p521_ecdsa_verify( // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    const uint8_t public_key_uncompressed[133], // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    const uint8_t msg_hash[64],                 // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    const uint8_t sig[132]) noexcept            // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
{
    using Fe = Fe521;
    using Point = P521Point;
    constexpr std::size_t qlen = 66; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    constexpr std::size_t hlen = 64; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)

    if (public_key_uncompressed[0] != 0x04U) { return false; }

    Fe r{}, s{};
    if (!p521_scalar_sig_decode(sig,          r)) { return false; } // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    if (!p521_scalar_sig_decode(sig + qlen,   s)) { return false; } // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)

    const Fe e = p521_scalar_from_bytes66_hash(msg_hash, hlen);
    const Fe w = p521_scalar_invert(s);

    const Fe u1 = p521_scalar_mul_mod_n(e, w);
    const Fe u2 = p521_scalar_mul_mod_n(r, w);

    uint8_t u1b[qlen] = {};
    uint8_t u2b[qlen] = {};
    fe521_to_bytes(u1, u1b);
    fe521_to_bytes(u2, u2b);

    // Reject non-canonical P-521 encodings: top 7 bits of each coordinate's first byte must be zero.
    if ((public_key_uncompressed[1]  & 0xFEU) != 0U) { return false; } // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    if ((public_key_uncompressed[67] & 0xFEU) != 0U) { return false; } // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic,cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    const Fe Qx = fe521_from_bytes(public_key_uncompressed + 1);   // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    const Fe Qy = fe521_from_bytes(public_key_uncompressed + 67);  // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic,cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    if (!p521_validate_public_point(Qx, Qy)) { return false; }
    const Point Q{.X = Qx, .Y = Qy, .Z = fe521_one};

    const Point X = p521_to_affine(p521_point_add(
        p521_scalar_mul_base(u1b),
        p521_scalar_mul(Q, u2b)));

    if (p521_point_is_identity(X)) { return false; }

    uint8_t xx_bytes[qlen] = {};
    fe521_to_bytes(X.X, xx_bytes);
    const Fe xr = p521_scalar_from_bytes66(xx_bytes);
    return fe521_equal(xr, r);
}


}  // namespace arm_asm::detail
