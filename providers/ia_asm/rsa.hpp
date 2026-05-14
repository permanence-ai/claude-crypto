// SPDX-License-Identifier: Apache-2.0

#pragma once

// RSA key store and operations for the IA ASM backend.
//
// All RSA math is pure C++ (arm_asm/rsa_bigint.hpp, rsa_der.hpp, rsa_keygen.hpp).
// OAEP/PSS padding uses ia_asm::detail SHA-384 (no NEON).
//
// Everything lives in arm_asm::detail to match the namespace the backend uses.

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <utility>

#include "defs.hpp"
#include "rsa_oaep.hpp"
#include "rsa_pss.hpp"
#include "secure_buffer.hpp"
#include "../arm_asm/random.hpp"
#include "../arm_asm/rsa_bigint.hpp"
#include "../arm_asm/rsa_der.hpp"
#include "../arm_asm/rsa_keygen.hpp"


namespace arm_asm::detail {


constexpr std::size_t rsa_key_store_capacity = 8;
constexpr unsigned int rsa_key_id_base       = 0xC000U;

// Maximum private key DER size for 4096-bit RSA (PKCS#1).
constexpr std::size_t rsa_max_private_key_bytes = 5000;

// Maximum public key DER size for 4096-bit RSA (SubjectPublicKeyInfo).
constexpr std::size_t rsa_max_public_key_bytes = 600;

enum class RsaKeyKind : uint8_t {
    None    = 0,
    Private = 1,  // PKCS#1 DER CRT private key
    Public  = 2,  // SubjectPublicKeyInfo DER public key
};

struct RsaKeySlot {
    FixedSecureBuffer<rsa_max_private_key_bytes> data;
    std::size_t len{0};
    std::size_t bits{0};
    RsaKeyKind kind{RsaKeyKind::None};
    bool in_use{false};
};

inline RsaKeySlot& rsa_key_slot(std::size_t idx) noexcept {
    static std::array<RsaKeySlot, rsa_key_store_capacity> slots{};
    return slots[idx];
}

[[nodiscard]]
inline unsigned int rsa_key_store_import(
    RsaKeyKind kind, std::size_t bits,
    const CryptoByte* key, std::size_t key_len) noexcept {
    if (key_len > rsa_max_private_key_bytes) { return 0U; }
    for (std::size_t i = 0; i < rsa_key_store_capacity; ++i) {
        if (!rsa_key_slot(i).in_use) {
            std::memcpy(rsa_key_slot(i).data.data(), key, key_len);
            rsa_key_slot(i).len    = key_len;
            rsa_key_slot(i).bits   = bits;
            rsa_key_slot(i).kind   = kind;
            rsa_key_slot(i).in_use = true;
            return static_cast<unsigned int>(i) + rsa_key_id_base;
        }
    }
    return 0U;
}

[[nodiscard]]
inline bool rsa_key_store_get(unsigned int id,
                               RsaKeyKind* out_kind, std::size_t* out_bits,
                               const CryptoByte** out_key, std::size_t* out_len) noexcept {
    if (id < rsa_key_id_base || (id - rsa_key_id_base) >= rsa_key_store_capacity) { return false; }
    const std::size_t idx = id - rsa_key_id_base;
    const RsaKeySlot& s = rsa_key_slot(idx);
    if (!s.in_use) { return false; }
    *out_kind = s.kind;
    *out_bits = s.bits;
    *out_key  = s.data.data();
    *out_len  = s.len;
    return true;
}

[[nodiscard]]
inline bool rsa_key_id_is_rsa(unsigned int id) noexcept {
    return id >= rsa_key_id_base && (id - rsa_key_id_base) < rsa_key_store_capacity;
}

inline void rsa_key_store_destroy(unsigned int id) noexcept {
    if (id < rsa_key_id_base || (id - rsa_key_id_base) >= rsa_key_store_capacity) { return; }
    const std::size_t idx = id - rsa_key_id_base;
    RsaKeySlot& s = rsa_key_slot(idx);
    s.data   = FixedSecureBuffer<rsa_max_private_key_bytes>{};
    s.len    = 0;
    s.bits   = 0;
    s.kind   = RsaKeyKind::None;
    s.in_use = false;
}


// -----------------------------------------------------------------------
// Dispatch helper: call the right template instantiation for modulus_bits.
// -----------------------------------------------------------------------

template<typename Fn>
[[nodiscard]]
inline bool rsa_dispatch(std::size_t bits, Fn&& fn) noexcept { // NOLINT(cppcoreguidelines-missing-std-forward)
    switch (bits) {
        case 2048U: return std::forward<Fn>(fn).template operator()<32U>();
        case 3072U: return std::forward<Fn>(fn).template operator()<48U>();
        case 4096U: return std::forward<Fn>(fn).template operator()<64U>();
        default: return false;
    }
}

template<typename Fn>
[[nodiscard]]
inline bool rsa_dispatch_all(std::size_t bits, Fn&& fn) noexcept { // NOLINT(cppcoreguidelines-missing-std-forward)
    switch (bits) {
        case 1024U: return std::forward<Fn>(fn).template operator()<16U>();
        case 2048U: return std::forward<Fn>(fn).template operator()<32U>();
        case 3072U: return std::forward<Fn>(fn).template operator()<48U>();
        case 4096U: return std::forward<Fn>(fn).template operator()<64U>();
        default: return false;
    }
}


// -----------------------------------------------------------------------
// Key generation.
// -----------------------------------------------------------------------

[[nodiscard]]
inline unsigned int rsa_generate_key_pair(
    std::size_t bits,
    CryptoByte* pub_out, std::size_t pub_max, std::size_t* pub_len) noexcept
{
    FixedSecureBuffer<rsa_max_private_key_bytes> priv_buf{};
    std::size_t priv_len = 0;

    const bool gen_ok = rsa_dispatch_all(bits, [&]<std::size_t NW>() -> bool {
        return rsa_generate_key_der<NW>(bits, priv_buf.data(),
                                         rsa_max_private_key_bytes, &priv_len);
    });
    if (!gen_ok) { return 0U; }

    if (!rsa_derive_public_key_der(priv_buf.data(), priv_len, pub_out, pub_max, pub_len)) {
        return 0U;
    }

    return rsa_key_store_import(RsaKeyKind::Private, bits, priv_buf.data(), priv_len);
}


// -----------------------------------------------------------------------
// RSA-OAEP encrypt (public key operation).
// Uses ia_asm::detail SHA-384 for OAEP padding.
// -----------------------------------------------------------------------

[[nodiscard]]
inline bool rsa_oaep_encrypt( // NOLINT(readability-function-cognitive-complexity,readability-function-size)
    std::size_t bits,
    const CryptoByte* pub_der, std::size_t pub_len,
    const CryptoByte* pt, std::size_t pt_len,
    const CryptoByte* label, std::size_t label_len,
    CryptoByte* ct_out, std::size_t ct_max, std::size_t* ct_len) noexcept
{
    RsaPublicKeyComponents pub{};
    if (!rsa_parse_public_key_der(pub_der, pub_len, pub)) { return false; }

    const std::size_t k = bits / 8U;
    if (ct_max < k) { return false; }
    if (pub.n_len != k) { return false; }

    ByteArray<ia_asm::detail::oaep_hash_len> seed{};
    generate_random_bytes(seed.data(), seed.size());

    FixedSecureBuffer<rsa_max_key_bytes + 1U> em{};
    if (!ia_asm::detail::oaep_encode(pt, pt_len, label, label_len, seed.data(), k, em.data())) { return false; }

    return rsa_dispatch_all(bits, [&]<std::size_t NW>() -> bool {
        rsa_public_op<NW>(em.data(), k, pub.n, pub.n_len, pub.e, pub.e_len, ct_out);
        *ct_len = k;
        return true;
    });
}


// -----------------------------------------------------------------------
// RSA-OAEP decrypt (private key operation).
// Uses ia_asm::detail SHA-384 for OAEP padding.
// -----------------------------------------------------------------------

[[nodiscard]]
inline bool rsa_oaep_decrypt( // NOLINT(readability-function-cognitive-complexity,readability-function-size)
    std::size_t bits,
    const CryptoByte* priv_der, std::size_t priv_len,
    const CryptoByte* ct, std::size_t ct_len,
    const CryptoByte* label, std::size_t label_len,
    CryptoByte* pt_out, std::size_t pt_max, std::size_t* pt_len) noexcept
{
    if (ct_len != bits / 8U) { return false; }

    RsaPrivateKeyComponents priv{};
    if (!rsa_parse_private_key_der(priv_der, priv_len, priv)) { return false; }

    const std::size_t k = bits / 8U;

    FixedSecureBuffer<rsa_max_key_bytes + 1U> em{};

    const bool ok = rsa_dispatch_all(bits, [&]<std::size_t NW>() -> bool {
        rsa_private_op<NW>(ct, ct_len,
                            priv.p,    priv.p_len,
                            priv.q,    priv.q_len,
                            priv.dp,   priv.dp_len,
                            priv.dq,   priv.dq_len,
                            priv.qinv, priv.qinv_len,
                            em.data());
        return true;
    });
    if (!ok) { return false; }

    return ia_asm::detail::oaep_decode(em.data(), k, label, label_len, pt_out, pt_max, pt_len);
}


// -----------------------------------------------------------------------
// RSA-PSS sign (private key operation).
// Uses ia_asm::detail SHA-384 for PSS encoding.
// -----------------------------------------------------------------------

[[nodiscard]]
inline bool rsa_pss_sign( // NOLINT(readability-function-cognitive-complexity,readability-function-size)
    std::size_t bits,
    const CryptoByte* priv_der, std::size_t priv_len,
    const CryptoByte* msg, std::size_t msg_len,
    CryptoByte* sig_out, std::size_t sig_max, std::size_t* sig_len) noexcept
{
    const std::size_t k = bits / 8U;
    if (sig_max < k) { return false; }

    RsaPrivateKeyComponents priv{};
    if (!rsa_parse_private_key_der(priv_der, priv_len, priv)) { return false; }

    ByteArray<ia_asm::detail::oaep_hash_len> salt{};
    generate_random_bytes(salt.data(), salt.size());

    FixedSecureBuffer<rsa_max_key_bytes + 1U> em{};
    if (!ia_asm::detail::pss_encode(msg, msg_len, salt.data(), bits, em.data())) { return false; }

    return rsa_dispatch_all(bits, [&]<std::size_t NW>() -> bool {
        rsa_private_op<NW>(em.data(), k,
                            priv.p,    priv.p_len,
                            priv.q,    priv.q_len,
                            priv.dp,   priv.dp_len,
                            priv.dq,   priv.dq_len,
                            priv.qinv, priv.qinv_len,
                            sig_out);
        *sig_len = k;
        return true;
    });
}


// -----------------------------------------------------------------------
// RSA-PSS verify (public key operation).
// Uses ia_asm::detail SHA-384 for PSS verification.
// -----------------------------------------------------------------------

[[nodiscard]]
inline bool rsa_pss_verify( // NOLINT(readability-function-cognitive-complexity,readability-function-size)
    std::size_t bits,
    const CryptoByte* pub_der, std::size_t pub_len,
    const CryptoByte* msg, std::size_t msg_len,
    const CryptoByte* sig, std::size_t sig_len) noexcept
{
    if (sig_len != bits / 8U) { return false; }

    RsaPublicKeyComponents pub{};
    if (!rsa_parse_public_key_der(pub_der, pub_len, pub)) { return false; }
    if (pub.n_len != bits / 8U) { return false; }

    FixedSecureBuffer<rsa_max_key_bytes + 1U> em{};

    const bool ok = rsa_dispatch_all(bits, [&]<std::size_t NW>() -> bool {
        rsa_public_op<NW>(sig, sig_len, pub.n, pub.n_len, pub.e, pub.e_len, em.data());
        return true;
    });
    if (!ok) { return false; }

    return ia_asm::detail::pss_verify(msg, msg_len, em.data(), bits);
}


}  // namespace arm_asm::detail
