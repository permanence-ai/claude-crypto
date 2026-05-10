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
    uint8_t* k_out) noexcept
{
    FixedSecureBuffer<66> V{};
    for (std::size_t i = 0; i < qlen; ++i) { V[i] = 0x01U; }

    FixedSecureBuffer<66> K{};

    FixedSecureBuffer<66 + 1 + 66 + 64> msg_buf{};

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

        if (qlen == 32) {
            hmac_sha256(K.data(), qlen, msg_buf.data(), off, std::span<uint8_t, 32>{K.data(), 32});
            hmac_sha256(K.data(), qlen, V.data(), qlen, std::span<uint8_t, 32>{V.data(), 32});
        } else if (qlen == 48) {
            hmac_sha384(K.data(), qlen, msg_buf.data(), off, std::span<uint8_t, 48>{K.data(), 48});
            hmac_sha384(K.data(), qlen, V.data(), qlen, std::span<uint8_t, 48>{V.data(), 48});
        } else {
            hmac_sha512(K.data(), qlen, msg_buf.data(), off, std::span<uint8_t, 64>{K.data(), 64});
            hmac_sha512(K.data(), qlen, V.data(), qlen, std::span<uint8_t, 64>{V.data(), 64});
        }
    }

    for (int attempt = 0; attempt < 100; ++attempt) {
        if (qlen == 32) {
            hmac_sha256(K.data(), qlen, V.data(), qlen, std::span<uint8_t, 32>{V.data(), 32});
        } else if (qlen == 48) {
            hmac_sha384(K.data(), qlen, V.data(), qlen, std::span<uint8_t, 48>{V.data(), 48});
        } else {
            hmac_sha512(K.data(), qlen, V.data(), qlen, std::span<uint8_t, 64>{V.data(), 64});
        }
        std::memcpy(k_out, V.data(), qlen);

        bool is_zero = true;
        for (std::size_t i = 0; i < qlen; ++i) {
            if (k_out[i] != 0U) { is_zero = false; break; }
        }
        if (is_zero) { goto update_kv; }  // NOLINT(cppcoreguidelines-avoid-goto,hicpp-avoid-goto)

        {
            const std::size_t n_bytes = n_limb_count * 8;
            bool k_lt_n = false;
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
        {
            FixedSecureBuffer<66 + 1> tmp{};
            std::memcpy(tmp.data(), V.data(), qlen);
            tmp[qlen] = 0x00U;
            if (qlen == 32) {
                hmac_sha256(K.data(), qlen, tmp.data(), qlen + 1, std::span<uint8_t, 32>{K.data(), 32});
                hmac_sha256(K.data(), qlen, V.data(), qlen, std::span<uint8_t, 32>{V.data(), 32});
            } else if (qlen == 48) {
                hmac_sha384(K.data(), qlen, tmp.data(), qlen + 1, std::span<uint8_t, 48>{K.data(), 48});
                hmac_sha384(K.data(), qlen, V.data(), qlen, std::span<uint8_t, 48>{V.data(), 48});
            } else {
                hmac_sha512(K.data(), qlen, tmp.data(), qlen + 1, std::span<uint8_t, 64>{K.data(), 64});
                hmac_sha512(K.data(), qlen, V.data(), qlen, std::span<uint8_t, 64>{V.data(), 64});
            }
        }
    }
}


static inline bool p256_ecdsa_sign(
    std::span<const uint8_t, 32> private_scalar_be,
    std::span<const uint8_t, 32> msg_hash,
    std::span<uint8_t, 64> sig_out) noexcept
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
    constexpr std::size_t qlen = 32;

    const Fe256 e = p256_scalar_from_bytes32(msg_hash);
    const Fe256 d = p256_scalar_from_bytes32(private_scalar_be);
    if (p256_scalar_is_zero(d)) { return false; }

    FixedSecureBuffer<qlen> k_buf{};
    rfc6979_generate_k(private_scalar_be.data(), qlen, msg_hash.data(), qlen,
                       p256_n.data(), 4, k_buf.data());

    const Fe256 k = p256_scalar_from_bytes32(std::span<const uint8_t, 32>{k_buf.data(), 32});
    if (p256_scalar_is_zero(k)) { return false; }

    const P256Point R = p256_to_affine(p256_scalar_mul_base(std::span<const uint8_t, 32>{k_buf.data(), 32}));
    if (p256_point_is_identity(R)) { return false; }

    std::array<uint8_t, qlen> rx_bytes{};
    fe256_to_bytes(R.X, rx_bytes);
    const Fe256 r = p256_scalar_from_bytes32(std::span<const uint8_t, 32>{rx_bytes.data(), 32});
    if (p256_scalar_is_zero(r)) { return false; }

    const Fe256 rd   = p256_scalar_mul_mod_n(r, d);
    const Fe256 eprd = p256_scalar_add(e, rd);
    const Fe256 kinv = p256_scalar_invert(k);
    const Fe256 s    = p256_scalar_mul_mod_n(kinv, eprd);
    if (p256_scalar_is_zero(s)) { return false; }

    fe256_to_bytes(r, std::span<uint8_t, 32>{sig_out.data(), 32});
    fe256_to_bytes(s, std::span<uint8_t, 32>{sig_out.data() + qlen, 32});
    return true;
}

static inline bool p256_ecdsa_verify(
    std::span<const uint8_t, 65> public_key_uncompressed,
    std::span<const uint8_t, 32> msg_hash,
    std::span<const uint8_t, 64> sig) noexcept
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
    constexpr std::size_t qlen = 32;

    if (public_key_uncompressed[0] != 0x04U) { return false; }

    Fe256 r{}, s{};
    if (!p256_scalar_sig_decode(std::span<const uint8_t, 32>{sig.data(),        32}, r)) { return false; }
    if (!p256_scalar_sig_decode(std::span<const uint8_t, 32>{sig.data() + qlen, 32}, s)) { return false; }

    const Fe256 e = p256_scalar_from_bytes32(msg_hash);
    const Fe256 w = p256_scalar_invert(s);

    const Fe256 u1 = p256_scalar_mul_mod_n(e, w);
    const Fe256 u2 = p256_scalar_mul_mod_n(r, w);

    std::array<uint8_t, qlen> u1b{};
    std::array<uint8_t, qlen> u2b{};
    fe256_to_bytes(u1, u1b);
    fe256_to_bytes(u2, u2b);

    const Fe256 Qx = fe256_from_bytes(std::span<const uint8_t, 32>{public_key_uncompressed.data() + 1,  32});
    const Fe256 Qy = fe256_from_bytes(std::span<const uint8_t, 32>{public_key_uncompressed.data() + 33, 32});
    if (!p256_validate_public_point(Qx, Qy)) { return false; }
    const P256Point Q{.X = Qx, .Y = Qy, .Z = fe256_one};

    const P256Point X = p256_to_affine(p256_point_add(
        p256_scalar_mul_base(std::span<const uint8_t, 32>{u1b.data(), 32}),
        p256_scalar_mul(Q,   std::span<const uint8_t, 32>{u2b.data(), 32})));

    if (p256_point_is_identity(X)) { return false; }

    std::array<uint8_t, qlen> xx_bytes{};
    fe256_to_bytes(X.X, xx_bytes);
    const Fe256 xr = p256_scalar_from_bytes32(std::span<const uint8_t, 32>{xx_bytes.data(), 32});
    return fe256_equal(xr, r);
}


static inline bool p384_ecdsa_sign(
    std::span<const uint8_t, 48> private_scalar_be,
    std::span<const uint8_t, 48> msg_hash,
    std::span<uint8_t, 96> sig_out) noexcept
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
    constexpr std::size_t qlen = 48;

    const Fe384 e = p384_scalar_from_bytes48(msg_hash);
    const Fe384 d = p384_scalar_from_bytes48(private_scalar_be);
    if (p384_scalar_is_zero(d)) { return false; }

    FixedSecureBuffer<qlen> k_buf{};
    rfc6979_generate_k(private_scalar_be.data(), qlen, msg_hash.data(), qlen,
                       p384_n.data(), 6, k_buf.data());

    const Fe384 k = p384_scalar_from_bytes48(std::span<const uint8_t, 48>{k_buf.data(), 48});
    if (p384_scalar_is_zero(k)) { return false; }

    const P384Point R = p384_to_affine(p384_scalar_mul_base(std::span<const uint8_t, 48>{k_buf.data(), 48}));
    if (p384_point_is_identity(R)) { return false; }

    std::array<uint8_t, qlen> rx_bytes{};
    fe384_to_bytes(R.X, rx_bytes);
    const Fe384 r = p384_scalar_from_bytes48(std::span<const uint8_t, 48>{rx_bytes.data(), 48});
    if (p384_scalar_is_zero(r)) { return false; }

    const Fe384 rd   = p384_scalar_mul_mod_n(r, d);
    const Fe384 eprd = p384_scalar_add(e, rd);
    const Fe384 kinv = p384_scalar_invert(k);
    const Fe384 s    = p384_scalar_mul_mod_n(kinv, eprd);
    if (p384_scalar_is_zero(s)) { return false; }

    fe384_to_bytes(r, std::span<uint8_t, 48>{sig_out.data(), 48});
    fe384_to_bytes(s, std::span<uint8_t, 48>{sig_out.data() + qlen, 48});
    return true;
}

static inline bool p384_ecdsa_verify(
    std::span<const uint8_t, 97> public_key_uncompressed,
    std::span<const uint8_t, 48> msg_hash,
    std::span<const uint8_t, 96> sig) noexcept
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
    constexpr std::size_t qlen = 48;

    if (public_key_uncompressed[0] != 0x04U) { return false; }

    Fe384 r{}, s{};
    if (!p384_scalar_sig_decode(std::span<const uint8_t, 48>{sig.data(),        48}, r)) { return false; }
    if (!p384_scalar_sig_decode(std::span<const uint8_t, 48>{sig.data() + qlen, 48}, s)) { return false; }

    const Fe384 e = p384_scalar_from_bytes48(msg_hash);
    const Fe384 w = p384_scalar_invert(s);

    const Fe384 u1 = p384_scalar_mul_mod_n(e, w);
    const Fe384 u2 = p384_scalar_mul_mod_n(r, w);

    std::array<uint8_t, qlen> u1b{};
    std::array<uint8_t, qlen> u2b{};
    fe384_to_bytes(u1, u1b);
    fe384_to_bytes(u2, u2b);

    const Fe384 Qx = fe384_from_bytes(std::span<const uint8_t, 48>{public_key_uncompressed.data() + 1,  48});
    const Fe384 Qy = fe384_from_bytes(std::span<const uint8_t, 48>{public_key_uncompressed.data() + 49, 48});
    if (!p384_validate_public_point(Qx, Qy)) { return false; }
    const P384Point Q{.X = Qx, .Y = Qy, .Z = fe384_one};

    const P384Point X = p384_to_affine(p384_point_add(
        p384_scalar_mul_base(std::span<const uint8_t, 48>{u1b.data(), 48}),
        p384_scalar_mul(Q,   std::span<const uint8_t, 48>{u2b.data(), 48})));

    if (p384_point_is_identity(X)) { return false; }

    std::array<uint8_t, qlen> xx_bytes{};
    fe384_to_bytes(X.X, xx_bytes);
    const Fe384 xr = p384_scalar_from_bytes48(std::span<const uint8_t, 48>{xx_bytes.data(), 48});
    return fe384_equal(xr, r);
}


static inline bool p521_ecdsa_sign(
    std::span<const uint8_t, 66> private_scalar_be,
    std::span<const uint8_t, 64> msg_hash,
    std::span<uint8_t, 132> sig_out) noexcept
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
    constexpr std::size_t qlen = 66;
    constexpr std::size_t hlen = 64;

    const Fe521 e = p521_scalar_from_bytes66_hash(msg_hash.data(), hlen);
    const Fe521 d = p521_scalar_from_bytes66(private_scalar_be);
    if (p521_scalar_is_zero(d)) { return false; }

    FixedSecureBuffer<qlen> k_buf{};
    rfc6979_generate_k(private_scalar_be.data(), qlen, msg_hash.data(), hlen,
                       p521_n.data(), 9, k_buf.data());

    const Fe521 k = p521_scalar_from_bytes66(std::span<const uint8_t, 66>{k_buf.data(), 66});
    if (p521_scalar_is_zero(k)) { return false; }

    const P521Point R = p521_to_affine(p521_scalar_mul_base(std::span<const uint8_t, 66>{k_buf.data(), 66}));
    if (p521_point_is_identity(R)) { return false; }

    std::array<uint8_t, qlen> rx_bytes{};
    fe521_to_bytes(R.X, rx_bytes);
    const Fe521 r = p521_scalar_from_bytes66(std::span<const uint8_t, 66>{rx_bytes.data(), 66});
    if (p521_scalar_is_zero(r)) { return false; }

    const Fe521 rd   = p521_scalar_mul_mod_n(r, d);
    const Fe521 eprd = p521_scalar_add(e, rd);
    const Fe521 kinv = p521_scalar_invert(k);
    const Fe521 s    = p521_scalar_mul_mod_n(kinv, eprd);
    if (p521_scalar_is_zero(s)) { return false; }

    fe521_to_bytes(r, std::span<uint8_t, 66>{sig_out.data(), 66});
    fe521_to_bytes(s, std::span<uint8_t, 66>{sig_out.data() + qlen, 66});
    return true;
}

static inline bool p521_ecdsa_verify(
    std::span<const uint8_t, 133> public_key_uncompressed,
    std::span<const uint8_t, 64> msg_hash,
    std::span<const uint8_t, 132> sig) noexcept
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
    constexpr std::size_t qlen = 66;
    constexpr std::size_t hlen = 64;

    if (public_key_uncompressed[0] != 0x04U) { return false; }

    Fe521 r{}, s{};
    if (!p521_scalar_sig_decode(std::span<const uint8_t, 66>{sig.data(),        66}, r)) { return false; }
    if (!p521_scalar_sig_decode(std::span<const uint8_t, 66>{sig.data() + qlen, 66}, s)) { return false; }

    const Fe521 e = p521_scalar_from_bytes66_hash(msg_hash.data(), hlen);
    const Fe521 w = p521_scalar_invert(s);

    const Fe521 u1 = p521_scalar_mul_mod_n(e, w);
    const Fe521 u2 = p521_scalar_mul_mod_n(r, w);

    std::array<uint8_t, qlen> u1b{};
    std::array<uint8_t, qlen> u2b{};
    fe521_to_bytes(u1, u1b);
    fe521_to_bytes(u2, u2b);

    if ((public_key_uncompressed[1]  & 0xFEU) != 0U) { return false; }
    if ((public_key_uncompressed[67] & 0xFEU) != 0U) { return false; }
    const Fe521 Qx = fe521_from_bytes(std::span<const uint8_t, 66>{public_key_uncompressed.data() + 1,  66});
    const Fe521 Qy = fe521_from_bytes(std::span<const uint8_t, 66>{public_key_uncompressed.data() + 67, 66});
    if (!p521_validate_public_point(Qx, Qy)) { return false; }
    const P521Point Q{.X = Qx, .Y = Qy, .Z = fe521_one};

    const P521Point X = p521_to_affine(p521_point_add(
        p521_scalar_mul_base(std::span<const uint8_t, 66>{u1b.data(), 66}),
        p521_scalar_mul(Q,   std::span<const uint8_t, 66>{u2b.data(), 66})));

    if (p521_point_is_identity(X)) { return false; }

    std::array<uint8_t, qlen> xx_bytes{};
    fe521_to_bytes(X.X, xx_bytes);
    const Fe521 xr = p521_scalar_from_bytes66(std::span<const uint8_t, 66>{xx_bytes.data(), 66});
    return fe521_equal(xr, r);
}

}  // namespace ia_asm::detail
