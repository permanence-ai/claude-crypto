// SPDX-License-Identifier: Apache-2.0

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
#include <span>

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

static inline void rfc6979_generate_k( // NOLINT(readability-function-cognitive-complexity,readability-function-size)
    const uint8_t* scalar_be, std::size_t qlen,
    const uint8_t* hash_be,   std::size_t hlen,
    const uint64_t* n_limbs,  std::size_t n_limb_count,
    uint8_t* k_out) noexcept
{
    // Step a: hash is h1 = H(m), already provided.
    // Step b: V = 0x01 * qlen
    FixedSecureBuffer<66> V{};
    for (std::size_t i = 0; i < qlen; ++i) { V[i] = 0x01U; }

    // Step c: K = 0x00 * qlen
    FixedSecureBuffer<66> K{};
    // K is already zero-initialized by FixedSecureBuffer.

    // Combine message for HMAC: V || 0x00 || x || h1
    // Max: qlen(66) + 1 + qlen(66) + hlen(64) = 197
    FixedSecureBuffer<66 + 1 + 66 + 64> msg_buf{};

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
            std::memcpy(msg_buf.data() + off + (qlen - hlen), hash_be, hlen);
        }
        off += qlen;

        if (qlen == p256_scalar_bytes) {
            hmac_sha256(K.data(), qlen, msg_buf.data(), off, std::span<CryptoByte, sha256_digest_bytes>{K.data(), sha256_digest_bytes});
            hmac_sha256(K.data(), qlen, V.data(), qlen, std::span<CryptoByte, sha256_digest_bytes>{V.data(), sha256_digest_bytes});
        } else if (qlen == p384_scalar_bytes) {
            hmac_sha384(K.data(), qlen, msg_buf.data(), off, std::span<CryptoByte, sha384_digest_bytes>{K.data(), sha384_digest_bytes});
            hmac_sha384(K.data(), qlen, V.data(), qlen, std::span<CryptoByte, sha384_digest_bytes>{V.data(), sha384_digest_bytes});
        } else {
            hmac_sha512(K.data(), qlen, msg_buf.data(), off, std::span<CryptoByte, sha512_digest_bytes>{K.data(), sha512_digest_bytes});
            hmac_sha512(K.data(), qlen, V.data(), qlen, std::span<CryptoByte, sha512_digest_bytes>{V.data(), sha512_digest_bytes});
        }
    }

    // Step h: generate candidate T until valid k found.
    // In practice the first candidate is almost always valid.
    for (int attempt = 0; attempt < 100; ++attempt) {
        if (qlen == p256_scalar_bytes) {
            hmac_sha256(K.data(), qlen, V.data(), qlen, std::span<CryptoByte, sha256_digest_bytes>{V.data(), sha256_digest_bytes});
        } else if (qlen == p384_scalar_bytes) {
            hmac_sha384(K.data(), qlen, V.data(), qlen, std::span<CryptoByte, sha384_digest_bytes>{V.data(), sha384_digest_bytes});
        } else {
            hmac_sha512(K.data(), qlen, V.data(), qlen, std::span<CryptoByte, sha512_digest_bytes>{V.data(), sha512_digest_bytes});
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
                    const std::size_t byte_pos = n_bytes - 1U - ((static_cast<std::size_t>(j) * 8U) + static_cast<std::size_t>(b));
                    if (byte_pos < qlen) {
                        k_limb |= static_cast<uint64_t>(k_out[byte_pos]) << (static_cast<unsigned>(b) * 8U);
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
            FixedSecureBuffer<66 + 1> tmp{};
            std::memcpy(tmp.data(), V.data(), qlen);
            tmp[qlen] = 0x00U;
            if (qlen == 32) {
                hmac_sha256(K.data(), qlen, tmp.data(), qlen + 1, std::span<CryptoByte, sha256_digest_bytes>{K.data(), sha256_digest_bytes});
                hmac_sha256(K.data(), qlen, V.data(), qlen, std::span<CryptoByte, sha256_digest_bytes>{V.data(), sha256_digest_bytes});
            } else if (qlen == p384_scalar_bytes) {
                hmac_sha384(K.data(), qlen, tmp.data(), qlen + 1, std::span<CryptoByte, sha384_digest_bytes>{K.data(), sha384_digest_bytes});
                hmac_sha384(K.data(), qlen, V.data(), qlen, std::span<CryptoByte, sha384_digest_bytes>{V.data(), sha384_digest_bytes});
            } else {
                hmac_sha512(K.data(), qlen, tmp.data(), qlen + 1, std::span<CryptoByte, sha512_digest_bytes>{K.data(), sha512_digest_bytes});
                hmac_sha512(K.data(), qlen, V.data(), qlen, std::span<CryptoByte, sha512_digest_bytes>{V.data(), sha512_digest_bytes});
            }
        }
    }
}


// -----------------------------------------------------------------------
// P-256 ECDSA.
// -----------------------------------------------------------------------

// Sign: private_scalar_be[32], msg_hash[32] → sig_out[64] (r‖s BE).
static inline bool p256_ecdsa_sign(
    std::span<const CryptoByte, p256_scalar_bytes> private_scalar_be,
    std::span<const CryptoByte, sha256_digest_bytes> msg_hash,
    std::span<CryptoByte, p256_sig_bytes> sig_out) noexcept
{
    using Fe = Fe256;
    using Point = P256Point;
    constexpr std::size_t qlen = p256_scalar_bytes;

    // Hash of message: e = H(m) reduced mod n.
    const Fe e = p256_scalar_from_bytes32(msg_hash);
    const Fe d = p256_scalar_from_bytes32(private_scalar_be);
    if (p256_scalar_is_zero(d)) { return false; }

    // Generate deterministic k via RFC 6979.
    FixedSecureBuffer<qlen> k_buf{};
    rfc6979_generate_k(private_scalar_be.data(), qlen, msg_hash.data(), qlen,
                       p256_n.data(), 4, k_buf.data());

    const Fe k = p256_scalar_from_bytes32(std::span<const CryptoByte, p256_scalar_bytes>{k_buf.data(), p256_scalar_bytes});
    if (p256_scalar_is_zero(k)) { return false; }

    // R = k·G, r = R.x mod n.
    const Point R = p256_to_affine(p256_scalar_mul_base(std::span<const CryptoByte, p256_scalar_bytes>{k_buf.data(), p256_scalar_bytes}));
    if (p256_point_is_identity(R)) { return false; }

    // r = R.x mod n (R.x is in [0, p-1]; n < p so just subtract n once if needed).
    std::array<CryptoByte, qlen> rx_bytes{};
    fe256_to_bytes(R.X, std::span<CryptoByte, p256_scalar_bytes>{rx_bytes.data(), p256_scalar_bytes});
    const Fe r = p256_scalar_from_bytes32(std::span<const CryptoByte, p256_scalar_bytes>{rx_bytes.data(), p256_scalar_bytes});
    if (p256_scalar_is_zero(r)) { return false; }

    // s = k^{-1} * (e + r*d) mod n.
    const Fe rd   = p256_scalar_mul_mod_n(r, d);
    const Fe eprd = p256_scalar_add(e, rd);
    const Fe kinv = p256_scalar_invert(k);
    const Fe s    = p256_scalar_mul_mod_n(kinv, eprd);
    if (p256_scalar_is_zero(s)) { return false; }

    // Output r‖s big-endian.
    fe256_to_bytes(r, std::span<CryptoByte, p256_scalar_bytes>{sig_out.data(), p256_scalar_bytes});
    fe256_to_bytes(s, std::span<CryptoByte, p256_scalar_bytes>{sig_out.data() + qlen, p256_scalar_bytes});
    return true;
}

// Verify: public_key_uncompressed[65] (0x04||x||y), msg_hash[32], sig[64] (r‖s BE).
static inline bool p256_ecdsa_verify(
    std::span<const CryptoByte, p256_public_key_bytes> public_key_uncompressed,
    std::span<const CryptoByte, sha256_digest_bytes> msg_hash,
    std::span<const CryptoByte, p256_sig_bytes> sig) noexcept
{
    using Fe = Fe256;
    using Point = P256Point;
    constexpr std::size_t qlen = p256_scalar_bytes;

    if (public_key_uncompressed[0] != 0x04U) { return false; }

    Fe r{}, s{};
    if (!p256_scalar_sig_decode(std::span<const CryptoByte, p256_scalar_bytes>{sig.data(),        p256_scalar_bytes}, r)) { return false; }
    if (!p256_scalar_sig_decode(std::span<const CryptoByte, p256_scalar_bytes>{sig.data() + qlen, p256_scalar_bytes}, s)) { return false; }

    const Fe e = p256_scalar_from_bytes32(msg_hash);
    const Fe w = p256_scalar_invert(s);

    const Fe u1 = p256_scalar_mul_mod_n(e, w);
    const Fe u2 = p256_scalar_mul_mod_n(r, w);

    // Encode u1, u2 as scalars.
    std::array<CryptoByte, qlen> u1b{};
    std::array<CryptoByte, qlen> u2b{};
    fe256_to_bytes(u1, std::span<CryptoByte, p256_scalar_bytes>{u1b.data(), p256_scalar_bytes});
    fe256_to_bytes(u2, std::span<CryptoByte, p256_scalar_bytes>{u2b.data(), p256_scalar_bytes});

    // Compute u1·G + u2·Q.
    const Fe Qx = fe256_from_bytes(std::span<const CryptoByte, p256_scalar_bytes>{public_key_uncompressed.data() + 1,  p256_scalar_bytes});
    const Fe Qy = fe256_from_bytes(std::span<const CryptoByte, p256_scalar_bytes>{public_key_uncompressed.data() + 33, p256_scalar_bytes});
    if (!p256_validate_public_point(Qx, Qy)) { return false; }
    const Point Q{.X = Qx, .Y = Qy, .Z = fe256_one};

    const Point X = p256_to_affine(p256_point_add(
        p256_scalar_mul_base(std::span<const CryptoByte, p256_scalar_bytes>{u1b.data(), p256_scalar_bytes}),
        p256_scalar_mul(Q,   std::span<const CryptoByte, p256_scalar_bytes>{u2b.data(), p256_scalar_bytes})));

    if (p256_point_is_identity(X)) { return false; }

    // Compare X.x mod n with r.
    std::array<CryptoByte, qlen> xx_bytes{};
    fe256_to_bytes(X.X, std::span<CryptoByte, p256_scalar_bytes>{xx_bytes.data(), p256_scalar_bytes});
    const Fe xr = p256_scalar_from_bytes32(std::span<const CryptoByte, p256_scalar_bytes>{xx_bytes.data(), p256_scalar_bytes});
    return fe256_equal(xr, r);
}


// -----------------------------------------------------------------------
// P-384 ECDSA.
// -----------------------------------------------------------------------

static inline bool p384_ecdsa_sign(
    std::span<const CryptoByte, p384_scalar_bytes> private_scalar_be,
    std::span<const CryptoByte, sha384_digest_bytes> msg_hash,
    std::span<CryptoByte, p384_sig_bytes> sig_out) noexcept
{
    using Fe = Fe384;
    using Point = P384Point;
    constexpr std::size_t qlen = p384_scalar_bytes;

    const Fe e = p384_scalar_from_bytes48(msg_hash);
    const Fe d = p384_scalar_from_bytes48(private_scalar_be);
    if (p384_scalar_is_zero(d)) { return false; }

    FixedSecureBuffer<qlen> k_buf{};
    rfc6979_generate_k(private_scalar_be.data(), qlen, msg_hash.data(), qlen,
                       p384_n.data(), 6, k_buf.data());

    const Fe k = p384_scalar_from_bytes48(std::span<const CryptoByte, p384_scalar_bytes>{k_buf.data(), p384_scalar_bytes});
    if (p384_scalar_is_zero(k)) { return false; }

    const Point R = p384_to_affine(p384_scalar_mul_base(std::span<const CryptoByte, p384_scalar_bytes>{k_buf.data(), p384_scalar_bytes}));
    if (p384_point_is_identity(R)) { return false; }

    std::array<CryptoByte, qlen> rx_bytes{};
    fe384_to_bytes(R.X, std::span<CryptoByte, p384_scalar_bytes>{rx_bytes.data(), p384_scalar_bytes});
    const Fe r = p384_scalar_from_bytes48(std::span<const CryptoByte, p384_scalar_bytes>{rx_bytes.data(), p384_scalar_bytes});
    if (p384_scalar_is_zero(r)) { return false; }

    const Fe rd   = p384_scalar_mul_mod_n(r, d);
    const Fe eprd = p384_scalar_add(e, rd);
    const Fe kinv = p384_scalar_invert(k);
    const Fe s    = p384_scalar_mul_mod_n(kinv, eprd);
    if (p384_scalar_is_zero(s)) { return false; }

    fe384_to_bytes(r, std::span<CryptoByte, p384_scalar_bytes>{sig_out.data(), p384_scalar_bytes});
    fe384_to_bytes(s, std::span<CryptoByte, p384_scalar_bytes>{sig_out.data() + qlen, p384_scalar_bytes});
    return true;
}

static inline bool p384_ecdsa_verify(
    std::span<const CryptoByte, p384_public_key_bytes> public_key_uncompressed,
    std::span<const CryptoByte, sha384_digest_bytes> msg_hash,
    std::span<const CryptoByte, p384_sig_bytes> sig) noexcept
{
    using Fe = Fe384;
    using Point = P384Point;
    constexpr std::size_t qlen = p384_scalar_bytes;

    if (public_key_uncompressed[0] != 0x04U) { return false; }

    Fe r{}, s{};
    if (!p384_scalar_sig_decode(std::span<const CryptoByte, p384_scalar_bytes>{sig.data(),        p384_scalar_bytes}, r)) { return false; }
    if (!p384_scalar_sig_decode(std::span<const CryptoByte, p384_scalar_bytes>{sig.data() + qlen, p384_scalar_bytes}, s)) { return false; }

    const Fe e = p384_scalar_from_bytes48(msg_hash);
    const Fe w = p384_scalar_invert(s);

    const Fe u1 = p384_scalar_mul_mod_n(e, w);
    const Fe u2 = p384_scalar_mul_mod_n(r, w);

    std::array<CryptoByte, qlen> u1b{};
    std::array<CryptoByte, qlen> u2b{};
    fe384_to_bytes(u1, std::span<CryptoByte, p384_scalar_bytes>{u1b.data(), p384_scalar_bytes});
    fe384_to_bytes(u2, std::span<CryptoByte, p384_scalar_bytes>{u2b.data(), p384_scalar_bytes});

    const Fe Qx = fe384_from_bytes(std::span<const CryptoByte, p384_scalar_bytes>{public_key_uncompressed.data() + 1,  p384_scalar_bytes});
    const Fe Qy = fe384_from_bytes(std::span<const CryptoByte, p384_scalar_bytes>{public_key_uncompressed.data() + 49, p384_scalar_bytes});
    if (!p384_validate_public_point(Qx, Qy)) { return false; }
    const Point Q{.X = Qx, .Y = Qy, .Z = fe384_one};

    const Point X = p384_to_affine(p384_point_add(
        p384_scalar_mul_base(std::span<const CryptoByte, p384_scalar_bytes>{u1b.data(), p384_scalar_bytes}),
        p384_scalar_mul(Q,   std::span<const CryptoByte, p384_scalar_bytes>{u2b.data(), p384_scalar_bytes})));

    if (p384_point_is_identity(X)) { return false; }

    std::array<CryptoByte, qlen> xx_bytes{};
    fe384_to_bytes(X.X, std::span<CryptoByte, p384_scalar_bytes>{xx_bytes.data(), p384_scalar_bytes});
    const Fe xr = p384_scalar_from_bytes48(std::span<const CryptoByte, p384_scalar_bytes>{xx_bytes.data(), p384_scalar_bytes});
    return fe384_equal(xr, r);
}


// -----------------------------------------------------------------------
// P-521 ECDSA.
// -----------------------------------------------------------------------

static inline bool p521_ecdsa_sign(
    std::span<const CryptoByte, p521_scalar_bytes> private_scalar_be,
    std::span<const CryptoByte, sha512_digest_bytes> msg_hash,
    std::span<CryptoByte, p521_sig_bytes> sig_out) noexcept
{
    using Fe = Fe521;
    using Point = P521Point;
    constexpr std::size_t qlen = p521_scalar_bytes;
    constexpr std::size_t hlen = sha512_digest_bytes;

    const Fe e = p521_scalar_from_bytes66_hash(msg_hash.data(), hlen);
    const Fe d = p521_scalar_from_bytes66(private_scalar_be);
    if (p521_scalar_is_zero(d)) { return false; }

    FixedSecureBuffer<qlen> k_buf{};
    rfc6979_generate_k(private_scalar_be.data(), qlen, msg_hash.data(), hlen,
                       p521_n.data(), 9, k_buf.data());

    const Fe k = p521_scalar_from_bytes66(std::span<const CryptoByte, p521_scalar_bytes>{k_buf.data(), p521_scalar_bytes});
    if (p521_scalar_is_zero(k)) { return false; }

    const Point R = p521_to_affine(p521_scalar_mul_base(std::span<const CryptoByte, p521_scalar_bytes>{k_buf.data(), p521_scalar_bytes}));
    if (p521_point_is_identity(R)) { return false; }

    std::array<CryptoByte, qlen> rx_bytes{};
    fe521_to_bytes(R.X, std::span<CryptoByte, p521_scalar_bytes>{rx_bytes.data(), p521_scalar_bytes});
    const Fe r = p521_scalar_from_bytes66(std::span<const CryptoByte, p521_scalar_bytes>{rx_bytes.data(), p521_scalar_bytes});
    if (p521_scalar_is_zero(r)) { return false; }

    const Fe rd   = p521_scalar_mul_mod_n(r, d);
    const Fe eprd = p521_scalar_add(e, rd);
    const Fe kinv = p521_scalar_invert(k);
    const Fe s    = p521_scalar_mul_mod_n(kinv, eprd);
    if (p521_scalar_is_zero(s)) { return false; }

    fe521_to_bytes(r, std::span<CryptoByte, p521_scalar_bytes>{sig_out.data(), p521_scalar_bytes});
    fe521_to_bytes(s, std::span<CryptoByte, p521_scalar_bytes>{sig_out.data() + qlen, p521_scalar_bytes});
    return true;
}

static inline bool p521_ecdsa_verify(
    std::span<const CryptoByte, p521_public_key_bytes> public_key_uncompressed,
    std::span<const CryptoByte, sha512_digest_bytes> msg_hash,
    std::span<const CryptoByte, p521_sig_bytes> sig) noexcept
{
    using Fe = Fe521;
    using Point = P521Point;
    constexpr std::size_t qlen = p521_scalar_bytes;
    constexpr std::size_t hlen = sha512_digest_bytes;

    if (public_key_uncompressed[0] != 0x04U) { return false; }

    Fe r{}, s{};
    if (!p521_scalar_sig_decode(std::span<const CryptoByte, p521_scalar_bytes>{sig.data(),        p521_scalar_bytes}, r)) { return false; }
    if (!p521_scalar_sig_decode(std::span<const CryptoByte, p521_scalar_bytes>{sig.data() + qlen, p521_scalar_bytes}, s)) { return false; }

    const Fe e = p521_scalar_from_bytes66_hash(msg_hash.data(), hlen);
    const Fe w = p521_scalar_invert(s);

    const Fe u1 = p521_scalar_mul_mod_n(e, w);
    const Fe u2 = p521_scalar_mul_mod_n(r, w);

    std::array<CryptoByte, qlen> u1b{};
    std::array<CryptoByte, qlen> u2b{};
    fe521_to_bytes(u1, std::span<CryptoByte, p521_scalar_bytes>{u1b.data(), p521_scalar_bytes});
    fe521_to_bytes(u2, std::span<CryptoByte, p521_scalar_bytes>{u2b.data(), p521_scalar_bytes});

    // Reject non-canonical P-521 encodings: top 7 bits of each coordinate's first byte must be zero.
    if ((public_key_uncompressed[1]  & 0xFEU) != 0U) { return false; }
    if ((public_key_uncompressed[67] & 0xFEU) != 0U) { return false; }
    const Fe Qx = fe521_from_bytes(std::span<const CryptoByte, p521_scalar_bytes>{public_key_uncompressed.data() + 1,  p521_scalar_bytes});
    const Fe Qy = fe521_from_bytes(std::span<const CryptoByte, p521_scalar_bytes>{public_key_uncompressed.data() + 67, p521_scalar_bytes});
    if (!p521_validate_public_point(Qx, Qy)) { return false; }
    const Point Q{.X = Qx, .Y = Qy, .Z = fe521_one};

    const Point X = p521_to_affine(p521_point_add(
        p521_scalar_mul_base(std::span<const CryptoByte, p521_scalar_bytes>{u1b.data(), p521_scalar_bytes}),
        p521_scalar_mul(Q,   std::span<const CryptoByte, p521_scalar_bytes>{u2b.data(), p521_scalar_bytes})));

    if (p521_point_is_identity(X)) { return false; }

    std::array<CryptoByte, qlen> xx_bytes{};
    fe521_to_bytes(X.X, std::span<CryptoByte, p521_scalar_bytes>{xx_bytes.data(), p521_scalar_bytes});
    const Fe xr = p521_scalar_from_bytes66(std::span<const CryptoByte, p521_scalar_bytes>{xx_bytes.data(), p521_scalar_bytes});
    return fe521_equal(xr, r);
}


}  // namespace arm_asm::detail
