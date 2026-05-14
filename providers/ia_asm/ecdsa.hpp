// SPDX-License-Identifier: Apache-2.0

#pragma once

// ECDSA sign and verify for P-256, P-384, and P-521 — IA ASM variant.
//
// Identical to providers/arm_asm/ecdsa.hpp except:
//  - RFC 6979 HMAC calls use ia_asm::detail::hmac_sha256/384/512 (x86 SHA-NI)
//  - EC math types/functions are still from arm_asm::detail (pure C++ bignum)
//
// See arm_asm/ecdsa.hpp for the full algorithm description.

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>

#include "hmac.hpp"
#include "secure_buffer.hpp"
#include "../arm_asm/p256_point.hpp"
#include "../arm_asm/p384_point.hpp"
#include "../arm_asm/p521_point.hpp"


namespace ia_asm::detail {

using arm_asm::detail::Fe256;
using arm_asm::detail::Fe384;
using arm_asm::detail::Fe521;
using arm_asm::detail::P256Point;
using arm_asm::detail::P384Point;
using arm_asm::detail::P521Point;
using arm_asm::detail::fe256_one;
using arm_asm::detail::fe384_one;
using arm_asm::detail::fe521_one;
using arm_asm::detail::p256_n;
using arm_asm::detail::p384_n;
using arm_asm::detail::p521_n;
using arm_asm::detail::p256_scalar_sig_decode;
using arm_asm::detail::p384_scalar_sig_decode;
using arm_asm::detail::p521_scalar_sig_decode;
using arm_asm::detail::p256_validate_public_point;
using arm_asm::detail::p384_validate_public_point;
using arm_asm::detail::p521_validate_public_point;


static inline void rfc6979_generate_k( // NOLINT(readability-function-cognitive-complexity,readability-function-size)
    const uint8_t* scalar_be, std::size_t qlen,
    const uint8_t* hash_be,   std::size_t hlen,
    const uint64_t* n_limbs,  std::size_t n_limb_count,
    uint8_t* k_out) noexcept  // NOLINT(readability-non-const-parameter)
{
    FixedSecureBuffer<p521_scalar_bytes> V{};
    for (std::size_t i = 0; i < qlen; ++i) { V[i] = 0x01U; }

    FixedSecureBuffer<p521_scalar_bytes> K{};

    // bits2octets always writes qlen bytes (zero-padded when hlen < qlen).
    // Max: qlen(66) + 1 + qlen(66) + qlen(66) = 199
    FixedSecureBuffer<p521_scalar_bytes + 1U + p521_scalar_bytes + p521_scalar_bytes> msg_buf{};

    for (int round = 0; round < 2; ++round) {
        std::size_t off = 0;
        std::memcpy(msg_buf.data() + off, V.data(), qlen); off += qlen;
        msg_buf[off] = static_cast<uint8_t>(round);
        ++off;
        std::memcpy(msg_buf.data() + off, scalar_be, qlen); off += qlen;
        if (hlen >= qlen) {
            std::memcpy(msg_buf.data() + off, hash_be, qlen);
        } else {
            std::memset(msg_buf.data() + off, 0, qlen - hlen);
            std::memcpy(msg_buf.data() + off + (qlen - hlen), hash_be, hlen);
        }
        off += qlen;

        if (qlen == p256_scalar_bytes) {
            hmac_sha256(K.data(), qlen, msg_buf.data(), off, ByteSpan<sha256_digest_bytes>{K.data(), sha256_digest_bytes});
            hmac_sha256(K.data(), qlen, V.data(), qlen, ByteSpan<sha256_digest_bytes>{V.data(), sha256_digest_bytes});
        } else if (qlen == p384_scalar_bytes) {
            hmac_sha384(K.data(), qlen, msg_buf.data(), off, ByteSpan<sha384_digest_bytes>{K.data(), sha384_digest_bytes});
            hmac_sha384(K.data(), qlen, V.data(), qlen, ByteSpan<sha384_digest_bytes>{V.data(), sha384_digest_bytes});
        } else {
            hmac_sha512(K.data(), qlen, msg_buf.data(), off, ByteSpan<sha512_digest_bytes>{K.data(), sha512_digest_bytes});
            hmac_sha512(K.data(), qlen, V.data(), qlen, ByteSpan<sha512_digest_bytes>{V.data(), sha512_digest_bytes});
        }
    }

    for (int attempt = 0; attempt < 100; ++attempt) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        if (qlen == p256_scalar_bytes) {
            hmac_sha256(K.data(), qlen, V.data(), qlen, ByteSpan<sha256_digest_bytes>{V.data(), sha256_digest_bytes});
        } else if (qlen == p384_scalar_bytes) {
            hmac_sha384(K.data(), qlen, V.data(), qlen, ByteSpan<sha384_digest_bytes>{V.data(), sha384_digest_bytes});
        } else {
            hmac_sha512(K.data(), qlen, V.data(), qlen, ByteSpan<sha512_digest_bytes>{V.data(), sha512_digest_bytes});
        }
        std::memcpy(k_out, V.data(), qlen);

        bool is_zero = true;
        for (std::size_t i = 0; i < qlen; ++i) {
            if (k_out[i] != 0U) { is_zero = false; break; }
        }
        if (is_zero) { goto update_kv; }  // NOLINT(cppcoreguidelines-avoid-goto,hicpp-avoid-goto)

        {
            const std::size_t n_bytes = n_limb_count * sizeof(uint64_t);
            bool k_lt_n = false;
            for (int j = static_cast<int>(n_limb_count) - 1; j >= 0; --j) {
                uint64_t k_limb = 0;
                for (std::size_t b = 0; b < bits_per_byte; ++b) {
                    const std::size_t byte_pos = n_bytes - 1U - ((static_cast<std::size_t>(j) * bits_per_byte) + b);
                    if (byte_pos < qlen) {
                        k_limb |= static_cast<uint64_t>(k_out[byte_pos]) << (static_cast<unsigned>(b) * bits_per_byte);
                    }
                }
                if (k_limb < n_limbs[j]) { k_lt_n = true; break; }
                if (k_limb > n_limbs[j]) { k_lt_n = false; break; }
            }
            if (k_lt_n) { return; }
        }

update_kv:
        {
            FixedSecureBuffer<p521_scalar_bytes + 1U> tmp{};
            std::memcpy(tmp.data(), V.data(), qlen);
            tmp[qlen] = 0x00U;
            if (qlen == p256_scalar_bytes) {
                hmac_sha256(K.data(), qlen, tmp.data(), qlen + 1, ByteSpan<sha256_digest_bytes>{K.data(), sha256_digest_bytes});
                hmac_sha256(K.data(), qlen, V.data(), qlen, ByteSpan<sha256_digest_bytes>{V.data(), sha256_digest_bytes});
            } else if (qlen == p384_scalar_bytes) {
                hmac_sha384(K.data(), qlen, tmp.data(), qlen + 1, ByteSpan<sha384_digest_bytes>{K.data(), sha384_digest_bytes});
                hmac_sha384(K.data(), qlen, V.data(), qlen, ByteSpan<sha384_digest_bytes>{V.data(), sha384_digest_bytes});
            } else {
                hmac_sha512(K.data(), qlen, tmp.data(), qlen + 1, ByteSpan<sha512_digest_bytes>{K.data(), sha512_digest_bytes});
                hmac_sha512(K.data(), qlen, V.data(), qlen, ByteSpan<sha512_digest_bytes>{V.data(), sha512_digest_bytes});
            }
        }
    }
}


static inline bool p256_ecdsa_sign(
    CByteSpan<p256_scalar_bytes> private_scalar_be, // NOLINT(bugprone-easily-swappable-parameters)
    CByteSpan<sha256_digest_bytes> msg_hash,
    ByteSpan<p256_sig_bytes> sig_out) noexcept
{
    using arm_asm::detail::p256_scalar_from_bytes32;
    using arm_asm::detail::p256_scalar_is_zero;
    using arm_asm::detail::p256_scalar_mul;
    using arm_asm::detail::p256_scalar_mul_base;
    using arm_asm::detail::p256_scalar_mul_mod_n;
    using arm_asm::detail::p256_scalar_add;
    using arm_asm::detail::p256_scalar_invert;
    using arm_asm::detail::p256_to_affine;
    using arm_asm::detail::p256_point_is_identity;
    using arm_asm::detail::fe256_to_bytes;
    constexpr std::size_t qlen = p256_scalar_bytes;

    const Fe256 e = p256_scalar_from_bytes32(msg_hash);
    const Fe256 d = p256_scalar_from_bytes32(private_scalar_be);
    if (p256_scalar_is_zero(d)) { return false; }

    FixedSecureBuffer<qlen> k_buf{};
    rfc6979_generate_k(private_scalar_be.data(), qlen, msg_hash.data(), qlen,
                       p256_n.data(), p256_bits / uint64_bits, k_buf.data());

    const Fe256 k = p256_scalar_from_bytes32(CByteSpan<p256_scalar_bytes>{k_buf.data(), p256_scalar_bytes});
    if (p256_scalar_is_zero(k)) { return false; }

    const P256Point R = p256_to_affine(p256_scalar_mul_base(CByteSpan<p256_scalar_bytes>{k_buf.data(), p256_scalar_bytes}));
    if (p256_point_is_identity(R)) { return false; }

    ByteArray<qlen> rx_bytes{};
    fe256_to_bytes(R.X, rx_bytes);
    const Fe256 r = p256_scalar_from_bytes32(CByteSpan<p256_scalar_bytes>{rx_bytes.data(), p256_scalar_bytes});
    if (p256_scalar_is_zero(r)) { return false; }

    const Fe256 rd   = p256_scalar_mul_mod_n(r, d);
    const Fe256 eprd = p256_scalar_add(e, rd);
    const Fe256 kinv = p256_scalar_invert(k);
    const Fe256 s    = p256_scalar_mul_mod_n(kinv, eprd);
    if (p256_scalar_is_zero(s)) { return false; }

    fe256_to_bytes(r, ByteSpan<p256_scalar_bytes>{sig_out.data(), p256_scalar_bytes});
    fe256_to_bytes(s, ByteSpan<p256_scalar_bytes>{sig_out.data() + qlen, p256_scalar_bytes});
    return true;
}

static inline bool p256_ecdsa_verify(
    CByteSpan<p256_public_key_bytes> public_key_uncompressed, // NOLINT(bugprone-easily-swappable-parameters)
    CByteSpan<sha256_digest_bytes> msg_hash,
    CByteSpan<p256_sig_bytes> sig) noexcept
{
    using arm_asm::detail::p256_scalar_from_bytes32;
    using arm_asm::detail::p256_scalar_mul;
    using arm_asm::detail::p256_scalar_mul_base;
    using arm_asm::detail::p256_scalar_mul_mod_n;
    using arm_asm::detail::p256_scalar_invert;
    using arm_asm::detail::p256_to_affine;
    using arm_asm::detail::p256_point_is_identity;
    using arm_asm::detail::p256_point_add;
    using arm_asm::detail::fe256_from_bytes;
    using arm_asm::detail::fe256_to_bytes;
    using arm_asm::detail::fe256_equal;
    constexpr std::size_t qlen = p256_scalar_bytes;

    if (public_key_uncompressed[0] != 0x04U) { return false; }

    Fe256 r{}; // NOLINT(readability-isolate-declaration)
    Fe256 s{};
    if (!p256_scalar_sig_decode(CByteSpan<p256_scalar_bytes>{sig.data(),        p256_scalar_bytes}, r)) { return false; }
    if (!p256_scalar_sig_decode(CByteSpan<p256_scalar_bytes>{sig.data() + qlen, p256_scalar_bytes}, s)) { return false; }

    const Fe256 e = p256_scalar_from_bytes32(msg_hash);
    const Fe256 w = p256_scalar_invert(s);

    const Fe256 u1 = p256_scalar_mul_mod_n(e, w);
    const Fe256 u2 = p256_scalar_mul_mod_n(r, w);

    ByteArray<qlen> u1b{};
    ByteArray<qlen> u2b{};
    fe256_to_bytes(u1, u1b);
    fe256_to_bytes(u2, u2b);

    const Fe256 Qx = fe256_from_bytes(CByteSpan<p256_scalar_bytes>{public_key_uncompressed.data() + 1,  p256_scalar_bytes});
    const Fe256 Qy = fe256_from_bytes(CByteSpan<p256_scalar_bytes>{public_key_uncompressed.data() + 33, p256_scalar_bytes});
    if (!p256_validate_public_point(Qx, Qy)) { return false; }
    const P256Point Q{.X = Qx, .Y = Qy, .Z = fe256_one};

    const P256Point X = p256_to_affine(p256_point_add(
        p256_scalar_mul_base(CByteSpan<p256_scalar_bytes>{u1b.data(), p256_scalar_bytes}),
        p256_scalar_mul(Q,   CByteSpan<p256_scalar_bytes>{u2b.data(), p256_scalar_bytes})));

    if (p256_point_is_identity(X)) { return false; }

    ByteArray<qlen> xx_bytes{};
    fe256_to_bytes(X.X, xx_bytes);
    const Fe256 xr = p256_scalar_from_bytes32(CByteSpan<p256_scalar_bytes>{xx_bytes.data(), p256_scalar_bytes});
    return fe256_equal(xr, r);
}


static inline bool p384_ecdsa_sign(
    CByteSpan<p384_scalar_bytes> private_scalar_be, // NOLINT(bugprone-easily-swappable-parameters)
    CByteSpan<sha384_digest_bytes> msg_hash,
    ByteSpan<p384_sig_bytes> sig_out) noexcept
{
    using arm_asm::detail::p384_scalar_from_bytes48;
    using arm_asm::detail::p384_scalar_is_zero;
    using arm_asm::detail::p384_scalar_mul;
    using arm_asm::detail::p384_scalar_mul_base;
    using arm_asm::detail::p384_scalar_mul_mod_n;
    using arm_asm::detail::p384_scalar_add;
    using arm_asm::detail::p384_scalar_invert;
    using arm_asm::detail::p384_to_affine;
    using arm_asm::detail::p384_point_is_identity;
    using arm_asm::detail::fe384_to_bytes;
    constexpr std::size_t qlen = p384_scalar_bytes;

    const Fe384 e = p384_scalar_from_bytes48(msg_hash);
    const Fe384 d = p384_scalar_from_bytes48(private_scalar_be);
    if (p384_scalar_is_zero(d)) { return false; }

    FixedSecureBuffer<qlen> k_buf{};
    rfc6979_generate_k(private_scalar_be.data(), qlen, msg_hash.data(), qlen,
                       p384_n.data(), p384_bits / uint64_bits, k_buf.data());

    const Fe384 k = p384_scalar_from_bytes48(CByteSpan<p384_scalar_bytes>{k_buf.data(), p384_scalar_bytes});
    if (p384_scalar_is_zero(k)) { return false; }

    const P384Point R = p384_to_affine(p384_scalar_mul_base(CByteSpan<p384_scalar_bytes>{k_buf.data(), p384_scalar_bytes}));
    if (p384_point_is_identity(R)) { return false; }

    ByteArray<qlen> rx_bytes{};
    fe384_to_bytes(R.X, rx_bytes);
    const Fe384 r = p384_scalar_from_bytes48(CByteSpan<p384_scalar_bytes>{rx_bytes.data(), p384_scalar_bytes});
    if (p384_scalar_is_zero(r)) { return false; }

    const Fe384 rd   = p384_scalar_mul_mod_n(r, d);
    const Fe384 eprd = p384_scalar_add(e, rd);
    const Fe384 kinv = p384_scalar_invert(k);
    const Fe384 s    = p384_scalar_mul_mod_n(kinv, eprd);
    if (p384_scalar_is_zero(s)) { return false; }

    fe384_to_bytes(r, ByteSpan<p384_scalar_bytes>{sig_out.data(), p384_scalar_bytes});
    fe384_to_bytes(s, ByteSpan<p384_scalar_bytes>{sig_out.data() + qlen, p384_scalar_bytes});
    return true;
}

static inline bool p384_ecdsa_verify(
    CByteSpan<p384_public_key_bytes> public_key_uncompressed, // NOLINT(bugprone-easily-swappable-parameters)
    CByteSpan<sha384_digest_bytes> msg_hash,
    CByteSpan<p384_sig_bytes> sig) noexcept
{
    using arm_asm::detail::p384_scalar_from_bytes48;
    using arm_asm::detail::p384_scalar_mul;
    using arm_asm::detail::p384_scalar_mul_base;
    using arm_asm::detail::p384_scalar_mul_mod_n;
    using arm_asm::detail::p384_scalar_invert;
    using arm_asm::detail::p384_to_affine;
    using arm_asm::detail::p384_point_is_identity;
    using arm_asm::detail::p384_point_add;
    using arm_asm::detail::fe384_from_bytes;
    using arm_asm::detail::fe384_to_bytes;
    using arm_asm::detail::fe384_equal;
    constexpr std::size_t qlen = p384_scalar_bytes;

    if (public_key_uncompressed[0] != 0x04U) { return false; }

    Fe384 r{}; // NOLINT(readability-isolate-declaration)
    Fe384 s{};
    if (!p384_scalar_sig_decode(CByteSpan<p384_scalar_bytes>{sig.data(),        p384_scalar_bytes}, r)) { return false; }
    if (!p384_scalar_sig_decode(CByteSpan<p384_scalar_bytes>{sig.data() + qlen, p384_scalar_bytes}, s)) { return false; }

    const Fe384 e = p384_scalar_from_bytes48(msg_hash);
    const Fe384 w = p384_scalar_invert(s);

    const Fe384 u1 = p384_scalar_mul_mod_n(e, w);
    const Fe384 u2 = p384_scalar_mul_mod_n(r, w);

    ByteArray<qlen> u1b{};
    ByteArray<qlen> u2b{};
    fe384_to_bytes(u1, u1b);
    fe384_to_bytes(u2, u2b);

    const Fe384 Qx = fe384_from_bytes(CByteSpan<p384_scalar_bytes>{public_key_uncompressed.data() + 1,  p384_scalar_bytes});
    const Fe384 Qy = fe384_from_bytes(CByteSpan<p384_scalar_bytes>{public_key_uncompressed.data() + 49, p384_scalar_bytes});
    if (!p384_validate_public_point(Qx, Qy)) { return false; }
    const P384Point Q{.X = Qx, .Y = Qy, .Z = fe384_one};

    const P384Point X = p384_to_affine(p384_point_add(
        p384_scalar_mul_base(CByteSpan<p384_scalar_bytes>{u1b.data(), p384_scalar_bytes}),
        p384_scalar_mul(Q,   CByteSpan<p384_scalar_bytes>{u2b.data(), p384_scalar_bytes})));

    if (p384_point_is_identity(X)) { return false; }

    ByteArray<qlen> xx_bytes{};
    fe384_to_bytes(X.X, xx_bytes);
    const Fe384 xr = p384_scalar_from_bytes48(CByteSpan<p384_scalar_bytes>{xx_bytes.data(), p384_scalar_bytes});
    return fe384_equal(xr, r);
}


static inline bool p521_ecdsa_sign(
    CByteSpan<p521_scalar_bytes> private_scalar_be, // NOLINT(bugprone-easily-swappable-parameters)
    CByteSpan<sha512_digest_bytes> msg_hash,
    ByteSpan<p521_sig_bytes> sig_out) noexcept
{
    using arm_asm::detail::p521_scalar_from_bytes66;
    using arm_asm::detail::p521_scalar_from_bytes66_hash;
    using arm_asm::detail::p521_scalar_is_zero;
    using arm_asm::detail::p521_scalar_mul;
    using arm_asm::detail::p521_scalar_mul_base;
    using arm_asm::detail::p521_scalar_mul_mod_n;
    using arm_asm::detail::p521_scalar_add;
    using arm_asm::detail::p521_scalar_invert;
    using arm_asm::detail::p521_to_affine;
    using arm_asm::detail::p521_point_is_identity;
    using arm_asm::detail::fe521_to_bytes;
    constexpr std::size_t qlen = p521_scalar_bytes;
    constexpr std::size_t hlen = sha512_digest_bytes;

    const Fe521 e = p521_scalar_from_bytes66_hash(msg_hash.data(), hlen);
    const Fe521 d = p521_scalar_from_bytes66(private_scalar_be);
    if (p521_scalar_is_zero(d)) { return false; }

    FixedSecureBuffer<qlen> k_buf{};
    rfc6979_generate_k(private_scalar_be.data(), qlen, msg_hash.data(), hlen,
                       p521_n.data(), (p521_bits + uint64_bits - 1U) / uint64_bits, k_buf.data());

    const Fe521 k = p521_scalar_from_bytes66(CByteSpan<p521_scalar_bytes>{k_buf.data(), p521_scalar_bytes});
    if (p521_scalar_is_zero(k)) { return false; }

    const P521Point R = p521_to_affine(p521_scalar_mul_base(CByteSpan<p521_scalar_bytes>{k_buf.data(), p521_scalar_bytes}));
    if (p521_point_is_identity(R)) { return false; }

    ByteArray<qlen> rx_bytes{};
    fe521_to_bytes(R.X, rx_bytes);
    const Fe521 r = p521_scalar_from_bytes66(CByteSpan<p521_scalar_bytes>{rx_bytes.data(), p521_scalar_bytes});
    if (p521_scalar_is_zero(r)) { return false; }

    const Fe521 rd   = p521_scalar_mul_mod_n(r, d);
    const Fe521 eprd = p521_scalar_add(e, rd);
    const Fe521 kinv = p521_scalar_invert(k);
    const Fe521 s    = p521_scalar_mul_mod_n(kinv, eprd);
    if (p521_scalar_is_zero(s)) { return false; }

    fe521_to_bytes(r, ByteSpan<p521_scalar_bytes>{sig_out.data(), p521_scalar_bytes});
    fe521_to_bytes(s, ByteSpan<p521_scalar_bytes>{sig_out.data() + qlen, p521_scalar_bytes});
    return true;
}

static inline bool p521_ecdsa_verify(
    CByteSpan<p521_public_key_bytes> public_key_uncompressed, // NOLINT(bugprone-easily-swappable-parameters)
    CByteSpan<sha512_digest_bytes> msg_hash,
    CByteSpan<p521_sig_bytes> sig) noexcept
{
    using arm_asm::detail::p521_scalar_from_bytes66;
    using arm_asm::detail::p521_scalar_from_bytes66_hash;
    using arm_asm::detail::p521_scalar_mul;
    using arm_asm::detail::p521_scalar_mul_base;
    using arm_asm::detail::p521_scalar_mul_mod_n;
    using arm_asm::detail::p521_scalar_invert;
    using arm_asm::detail::p521_to_affine;
    using arm_asm::detail::p521_point_is_identity;
    using arm_asm::detail::p521_point_add;
    using arm_asm::detail::fe521_from_bytes;
    using arm_asm::detail::fe521_to_bytes;
    using arm_asm::detail::fe521_equal;
    constexpr std::size_t qlen = p521_scalar_bytes;
    constexpr std::size_t hlen = sha512_digest_bytes;

    if (public_key_uncompressed[0] != 0x04U) { return false; }

    Fe521 r{}; // NOLINT(readability-isolate-declaration)
    Fe521 s{};
    if (!p521_scalar_sig_decode(CByteSpan<p521_scalar_bytes>{sig.data(),        p521_scalar_bytes}, r)) { return false; }
    if (!p521_scalar_sig_decode(CByteSpan<p521_scalar_bytes>{sig.data() + qlen, p521_scalar_bytes}, s)) { return false; }

    const Fe521 e = p521_scalar_from_bytes66_hash(msg_hash.data(), hlen);
    const Fe521 w = p521_scalar_invert(s);

    const Fe521 u1 = p521_scalar_mul_mod_n(e, w);
    const Fe521 u2 = p521_scalar_mul_mod_n(r, w);

    ByteArray<qlen> u1b{};
    ByteArray<qlen> u2b{};
    fe521_to_bytes(u1, u1b);
    fe521_to_bytes(u2, u2b);

    constexpr std::size_t p521_y_offset = 1U + p521_scalar_bytes;  // offset of y coord in uncompressed point
    if ((public_key_uncompressed[1]             & p521_top_byte_mask) != 0U) { return false; } // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    if ((public_key_uncompressed[p521_y_offset] & p521_top_byte_mask) != 0U) { return false; } // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    const Fe521 Qx = fe521_from_bytes(CByteSpan<p521_scalar_bytes>{public_key_uncompressed.data() + 1,              p521_scalar_bytes});
    const Fe521 Qy = fe521_from_bytes(CByteSpan<p521_scalar_bytes>{public_key_uncompressed.data() + p521_y_offset,  p521_scalar_bytes});
    if (!p521_validate_public_point(Qx, Qy)) { return false; }
    const P521Point Q{.X = Qx, .Y = Qy, .Z = fe521_one};

    const P521Point X = p521_to_affine(p521_point_add(
        p521_scalar_mul_base(CByteSpan<p521_scalar_bytes>{u1b.data(), p521_scalar_bytes}),
        p521_scalar_mul(Q,   CByteSpan<p521_scalar_bytes>{u2b.data(), p521_scalar_bytes})));

    if (p521_point_is_identity(X)) { return false; }

    ByteArray<qlen> xx_bytes{};
    fe521_to_bytes(X.X, xx_bytes);
    const Fe521 xr = p521_scalar_from_bytes66(CByteSpan<p521_scalar_bytes>{xx_bytes.data(), p521_scalar_bytes});
    return fe521_equal(xr, r);
}

}  // namespace ia_asm::detail
