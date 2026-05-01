/*
Copyright Permanence AI, 2026. All rights reserved.

*/

#pragma once

// RSA key store and operations for the ARM ASM backend.
//
// RSA operations are delegated to PSA/MbedTLS because RSA does not benefit
// from ARM Crypto Extension intrinsics (no hardware acceleration on AArch64
// for big-integer arithmetic).
//
// Supported:
//   - RSA-OAEP-3072/4096 encrypt/decrypt (SHA-384 mask/label hash)
//   - RSA-PSS-3072/4096 sign/verify (SHA-384)
//   - Key generation (CRT key pair), export as PKCS#1 DER
//
// Key format (PSA raw export):
//   Private key: PKCS#1 RSAPrivateKey DER
//   Public key:  SubjectPublicKeyInfo DER (RSAPublicKey wrapped)
//
// Key store:
//   Separate from the symmetric key store; 8 slots.
//   RsaKeyId = rsa_key_id_base + slot (rsa_key_id_base = 0xC000)

#include <cstddef>
#include <cstdint>
#include <cstring>

#include <psa/crypto.h>
#include <psa/crypto_sizes.h>
#include <psa/crypto_values.h>

#include "defs.hpp"
#include "secure_buffer.hpp"


namespace arm_asm::detail {


constexpr std::size_t rsa_key_store_capacity = 8;
constexpr unsigned int rsa_key_id_base       = 0xC000U;

// Maximum private key DER size for 4096-bit RSA.
// PSA_KEY_EXPORT_RSA_KEY_PAIR_MAX_SIZE(4096) = 9 * (4096/2/8+1+5) + 14 = 9*266+14 = 2408
// Use 2450 for safety margin.
constexpr std::size_t rsa_max_private_key_bytes = 2450;

// Maximum public key DER size for 4096-bit RSA.
// PSA_KEY_EXPORT_RSA_PUBLIC_KEY_MAX_SIZE(4096) = 4096/8+5+11 = 528
// Use 550 for safety margin.
constexpr std::size_t rsa_max_public_key_bytes = 550;

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
    static RsaKeySlot slots[rsa_key_store_capacity]{}; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
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
    RsaKeySlot& s = rsa_key_slot(idx);
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
// PSA algorithm selectors for RSA-OAEP and RSA-PSS (both with SHA-384).
// -----------------------------------------------------------------------

inline psa_algorithm_t rsa_oaep_alg() noexcept { return PSA_ALG_RSA_OAEP(PSA_ALG_SHA_384); }
inline psa_algorithm_t rsa_pss_alg()  noexcept { return PSA_ALG_RSA_PSS(PSA_ALG_SHA_384); }


// -----------------------------------------------------------------------
// Key generation.
// -----------------------------------------------------------------------

// Generates an RSA key pair of the given bit size using PSA.
// Exports the private and public keys as DER-encoded byte strings.
// Stores the private key in the RSA key store and returns its ID.
// Also exports the public key separately (stored in pub_out/pub_len).
[[nodiscard]]
inline unsigned int rsa_generate_key_pair(
    std::size_t bits,
    CryptoByte* pub_out, std::size_t pub_max, std::size_t* pub_len) noexcept
{
    psa_crypto_init();

    // Generate with both OAEP and PSS usage flags so the single key works for both.
    psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attrs, PSA_KEY_TYPE_RSA_KEY_PAIR);
    psa_set_key_bits(&attrs, static_cast<psa_key_bits_t>(bits));
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT |
                                    PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE |
                                    PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attrs, rsa_oaep_alg());

    mbedtls_svc_key_id_t psa_id = MBEDTLS_SVC_KEY_ID_INIT;
    if (psa_generate_key(&attrs, &psa_id) != PSA_SUCCESS) { return 0U; }

    // Export private key as PKCS#1 DER.
    FixedSecureBuffer<rsa_max_private_key_bytes> priv_buf{};
    std::size_t priv_len = 0;
    if (psa_export_key(psa_id, priv_buf.data(), rsa_max_private_key_bytes, &priv_len) != PSA_SUCCESS) {
        psa_destroy_key(psa_id);
        return 0U;
    }

    // Export public key as SubjectPublicKeyInfo DER.
    if (psa_export_public_key(psa_id, pub_out, pub_max, pub_len) != PSA_SUCCESS) {
        psa_destroy_key(psa_id);
        return 0U;
    }

    psa_destroy_key(psa_id);

    return rsa_key_store_import(RsaKeyKind::Private, bits, priv_buf.data(), priv_len);
}


// -----------------------------------------------------------------------
// RSA-OAEP encrypt.
// -----------------------------------------------------------------------

[[nodiscard]]
inline bool rsa_oaep_encrypt( // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    std::size_t bits,
    const CryptoByte* pub_der, std::size_t pub_len,
    const CryptoByte* pt, std::size_t pt_len,
    const CryptoByte* label, std::size_t label_len,
    CryptoByte* ct_out, std::size_t ct_max, std::size_t* ct_len) noexcept
{
    psa_crypto_init();

    psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attrs, PSA_KEY_TYPE_RSA_PUBLIC_KEY);
    psa_set_key_bits(&attrs, static_cast<psa_key_bits_t>(bits));
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attrs, rsa_oaep_alg());

    mbedtls_svc_key_id_t psa_id = MBEDTLS_SVC_KEY_ID_INIT;
    if (psa_import_key(&attrs, pub_der, pub_len, &psa_id) != PSA_SUCCESS) { return false; }

    const psa_status_t s = psa_asymmetric_encrypt(
        psa_id, rsa_oaep_alg(),
        pt, pt_len,
        label, label_len,
        ct_out, ct_max, ct_len);

    psa_destroy_key(psa_id);
    return s == PSA_SUCCESS;
}


// -----------------------------------------------------------------------
// RSA-OAEP decrypt.
// -----------------------------------------------------------------------

[[nodiscard]]
inline bool rsa_oaep_decrypt( // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    std::size_t bits,
    const CryptoByte* priv_der, std::size_t priv_len,
    const CryptoByte* ct, std::size_t ct_len,
    const CryptoByte* label, std::size_t label_len,
    CryptoByte* pt_out, std::size_t pt_max, std::size_t* pt_len) noexcept
{
    psa_crypto_init();

    psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attrs, PSA_KEY_TYPE_RSA_KEY_PAIR);
    psa_set_key_bits(&attrs, static_cast<psa_key_bits_t>(bits));
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attrs, rsa_oaep_alg());

    mbedtls_svc_key_id_t psa_id = MBEDTLS_SVC_KEY_ID_INIT;
    if (psa_import_key(&attrs, priv_der, priv_len, &psa_id) != PSA_SUCCESS) { return false; }

    const psa_status_t s = psa_asymmetric_decrypt(
        psa_id, rsa_oaep_alg(),
        ct, ct_len,
        label, label_len,
        pt_out, pt_max, pt_len);

    psa_destroy_key(psa_id);
    return s == PSA_SUCCESS;
}


// -----------------------------------------------------------------------
// RSA-PSS sign.
// -----------------------------------------------------------------------

[[nodiscard]]
inline bool rsa_pss_sign( // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    std::size_t bits,
    const CryptoByte* priv_der, std::size_t priv_len,
    const CryptoByte* msg, std::size_t msg_len,
    CryptoByte* sig_out, std::size_t sig_max, std::size_t* sig_len) noexcept
{
    psa_crypto_init();

    psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attrs, PSA_KEY_TYPE_RSA_KEY_PAIR);
    psa_set_key_bits(&attrs, static_cast<psa_key_bits_t>(bits));
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attrs, rsa_pss_alg());

    mbedtls_svc_key_id_t psa_id = MBEDTLS_SVC_KEY_ID_INIT;
    if (psa_import_key(&attrs, priv_der, priv_len, &psa_id) != PSA_SUCCESS) { return false; }

    const psa_status_t s = psa_sign_message(
        psa_id, rsa_pss_alg(),
        msg, msg_len,
        sig_out, sig_max, sig_len);

    psa_destroy_key(psa_id);
    return s == PSA_SUCCESS;
}


// -----------------------------------------------------------------------
// RSA-PSS verify.
// -----------------------------------------------------------------------

[[nodiscard]]
inline bool rsa_pss_verify( // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    std::size_t bits,
    const CryptoByte* pub_der, std::size_t pub_len,
    const CryptoByte* msg, std::size_t msg_len,
    const CryptoByte* sig, std::size_t sig_len) noexcept
{
    psa_crypto_init();

    psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attrs, PSA_KEY_TYPE_RSA_PUBLIC_KEY);
    psa_set_key_bits(&attrs, static_cast<psa_key_bits_t>(bits));
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(&attrs, rsa_pss_alg());

    mbedtls_svc_key_id_t psa_id = MBEDTLS_SVC_KEY_ID_INIT;
    if (psa_import_key(&attrs, pub_der, pub_len, &psa_id) != PSA_SUCCESS) { return false; }

    const psa_status_t s = psa_verify_message(
        psa_id, rsa_pss_alg(),
        msg, msg_len,
        sig, sig_len);

    psa_destroy_key(psa_id);
    return s == PSA_SUCCESS;
}


}  // namespace arm_asm::detail
