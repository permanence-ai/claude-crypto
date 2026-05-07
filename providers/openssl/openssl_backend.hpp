// SPDX-License-Identifier: Apache-2.0

#pragma once

// OpenSSL 3.x backend — implements the CryptoProvider concept using the
// OpenSSL EVP high-level API.
//
// Implementation status (symmetric crypto):
//   hash_compute          ✓  EVP_Q_digest
//   mac_compute/verify    TODO
//   aead_encrypt/decrypt  TODO
//   key_derivation_*      TODO
//
// Pending (asymmetric crypto):
//   sign/verify_message   TODO  EVP_DigestSign / EVP_DigestVerify (ECDSA)
//   raw_key_agreement     TODO  EVP_PKEY_derive (ECDH)
//   asymmetric_encrypt/decrypt  TODO  EVP_PKEY_encrypt / EVP_PKEY_decrypt (RSA-OAEP)
//   generate_key          TODO  EVP_PKEY_keygen_init / EVP_PKEY_generate
//   import_key/export_key TODO  EVP_PKEY_new_raw_private_key / d2i_* / i2d_*
//
// Key storage:
//   Asymmetric keys (EVP_PKEY*)  → ossl_asym_store, IDs   1..64
//   Symmetric / raw-byte keys    → ossl_raw_store,  IDs  65..128

#include <cstddef>
#include <cstdint>
#include <cstring>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

#include "defs.hpp"
#include "ml_dsa_variant.hpp"
#include "ml_kem_variant.hpp"
#include "openssl_key_store.hpp"
#include "sha_variant.hpp"
#include "slh_dsa_variant.hpp"


struct OpenSslBackend {
    // -------------------------------------------------------------------------
    // Associated types.
    //
    // Status  — int; 1 = success (OSSL_RV_OK), 0 = failure (OSSL_RV_ERR).
    //           Most OpenSSL EVP functions return 1 on success, 0 or negative
    //           on failure — this matches the PSA model of a scalar status.
    // KeyId   — unsigned int; maps to a slot in one of the two key stores.
    // Algorithm — uint32_t tag encoding which algorithm/variant to use.
    // KeyAttributes — lightweight struct carrying key type, size, and usage.
    // KdfOperation  — opaque struct holding EVP_KDF_CTX* and accumulated params.
    // KdfStep       — uint8_t tag identifying which HKDF input is being fed.
    // -------------------------------------------------------------------------

    using Status = int;
    using KeyId  = unsigned int;

    // Algorithm tag: upper 8 bits = family, lower 24 bits = variant/bits.
    using Algorithm = uint32_t;

    struct KeyAttributes {
        enum class KeyType : uint8_t {
            None, Aes256, ChaCha20, Hmac, Derive,
            EcKeyPair, EcPublicKey,
            RsaKeyPair, RsaPublicKey,
            SlhDsaKeyPair, SlhDsaPublicKey,
            MlDsaKeyPair, MlDsaPublicKey,
            MlKemKeyPair, MlKemPublicKey,
        };
        KeyType     type{KeyType::None};
        std::size_t bits{0};
        uint8_t     usage{0};    // bitmask of Usage flags below
        Algorithm   alg{0};

        enum Usage : uint8_t {
            Encrypt = 0x01, Decrypt = 0x02,
            Sign    = 0x04, Verify  = 0x08,
            Derive  = 0x10, Export  = 0x20,
        };
    };

    struct KdfOperation {
        EVP_KDF_CTX* ctx{nullptr};
        // Accumulated HKDF parameters — filled in by key_derivation_input_*.
        const CryptoByte* secret{nullptr};  std::size_t secret_len{0};
        const CryptoByte* salt{nullptr};    std::size_t salt_len{0};
        const CryptoByte* info{nullptr};    std::size_t info_len{0};
        // Whether a secret key (vs raw bytes) was supplied for the secret step.
        unsigned int secret_key_id{0};
        // EVP_KDF HKDF mode: extract+expand (full HKDF) or expand-only.
        int mode{0};
    };

    using KdfStep = uint8_t;

    // -------------------------------------------------------------------------
    // Status sentinels.
    // -------------------------------------------------------------------------
    static constexpr Status ok              = 1;
    static constexpr Status err_invalid_sig = 0;
    static constexpr Status err_invalid_arg = -1;

    // -------------------------------------------------------------------------
    // Algorithm tag constants.
    // -------------------------------------------------------------------------
    static constexpr Algorithm kAlgSha256          = 0x01'000000U;
    static constexpr Algorithm kAlgSha384          = 0x01'000001U;
    static constexpr Algorithm kAlgSha512          = 0x01'000002U;
    static constexpr Algorithm kAlgSha3_256        = 0x01'000003U;
    static constexpr Algorithm kAlgSha3_384        = 0x01'000004U;
    static constexpr Algorithm kAlgSha3_512        = 0x01'000005U;
    static constexpr Algorithm kAlgHmacSha256      = 0x02'000000U;
    static constexpr Algorithm kAlgHmacSha384      = 0x02'000001U;
    static constexpr Algorithm kAlgHmacSha512      = 0x02'000002U;
    static constexpr Algorithm kAlgHmacSha3_256    = 0x02'000003U;
    static constexpr Algorithm kAlgHmacSha3_384    = 0x02'000004U;
    static constexpr Algorithm kAlgHmacSha3_512    = 0x02'000005U;
    static constexpr Algorithm kAlgEcdsa           = 0x03'000000U;
    static constexpr Algorithm kAlgEcdh            = 0x04'000000U;
    static constexpr Algorithm kAlgHkdf            = 0x05'000000U;
    static constexpr Algorithm kAlgHkdfExpand      = 0x05'000001U;
    static constexpr Algorithm kAlgAesGcm          = 0x06'000000U;
    static constexpr Algorithm kAlgChaCha20Poly    = 0x07'000000U;
    static constexpr Algorithm kAlgRsaOaep         = 0x08'000000U;
    static constexpr Algorithm kAlgRsaPss          = 0x09'000000U;
    // SLH-DSA SHA2 variants: lower 8 bits = SlhDsaVariant enum value.
    static constexpr Algorithm kAlgSlhDsaBase      = 0x0A'000000U;
    // ML-DSA variants: lower 8 bits = MlDsaVariant enum value.
    static constexpr Algorithm kAlgMlDsaBase       = 0x0B'000000U;
    // ML-KEM variants: lower 8 bits = MlKemVariant enum value.
    static constexpr Algorithm kAlgMlKemBase       = 0x0C'000000U;

    // KDF step tags (mirror PSA_KEY_DERIVATION_INPUT_* semantics).
    static constexpr KdfStep kKdfStepSecret = 0x01U;
    static constexpr KdfStep kKdfStepSalt   = 0x02U;
    static constexpr KdfStep kKdfStepInfo   = 0x03U;

    // -------------------------------------------------------------------------
    // Object factories.
    // -------------------------------------------------------------------------
    [[nodiscard]]
    static KeyId null_key_id() noexcept { return 0U; }

    [[nodiscard]]
    static KeyAttributes make_key_attrs() noexcept { return {}; }

    [[nodiscard]]
    static KdfOperation make_kdf_op() noexcept { return {}; }

    // -------------------------------------------------------------------------
    // Algorithm constants — required by the CryptoProvider concept.
    // -------------------------------------------------------------------------
    [[nodiscard]]
    static Algorithm alg_sha(const ShaVariant v) noexcept {
        switch (v) {
            case ShaVariant::Sha256:   return kAlgSha256;
            case ShaVariant::Sha384:   return kAlgSha384;
            case ShaVariant::Sha512:   return kAlgSha512;
            case ShaVariant::Sha3_256: return kAlgSha3_256;
            case ShaVariant::Sha3_384: return kAlgSha3_384;
            case ShaVariant::Sha3_512: return kAlgSha3_512;
        }
    }
    [[nodiscard]]
    static Algorithm alg_hmac(const ShaVariant v) noexcept {
        switch (v) {
            case ShaVariant::Sha256:   return kAlgHmacSha256;
            case ShaVariant::Sha384:   return kAlgHmacSha384;
            case ShaVariant::Sha512:   return kAlgHmacSha512;
            case ShaVariant::Sha3_256: return kAlgHmacSha3_256;
            case ShaVariant::Sha3_384: return kAlgHmacSha3_384;
            case ShaVariant::Sha3_512: return kAlgHmacSha3_512;
        }
    }
    [[nodiscard]] static constexpr Algorithm alg_ecdsa()              noexcept { return kAlgEcdsa; }
    [[nodiscard]] static constexpr Algorithm alg_ecdh()               noexcept { return kAlgEcdh; }
    [[nodiscard]] static constexpr Algorithm alg_hkdf()               noexcept { return kAlgHkdf; }
    [[nodiscard]] static constexpr Algorithm alg_hkdf_expand()        noexcept { return kAlgHkdfExpand; }
    [[nodiscard]] static constexpr Algorithm alg_aes_gcm()            noexcept { return kAlgAesGcm; }
    [[nodiscard]] static constexpr Algorithm alg_chacha20_poly1305()  noexcept { return kAlgChaCha20Poly; }
    [[nodiscard]] static constexpr Algorithm alg_rsa_oaep()           noexcept { return kAlgRsaOaep; }
    [[nodiscard]] static constexpr Algorithm alg_rsa_pss()            noexcept { return kAlgRsaPss; }
    [[nodiscard]]
    static Algorithm alg_slh_dsa(const SlhDsaVariant v) noexcept {
        return kAlgSlhDsaBase | static_cast<Algorithm>(v);
    }
    [[nodiscard]]
    static Algorithm alg_ml_dsa(const MlDsaVariant v) noexcept {
        return kAlgMlDsaBase | static_cast<Algorithm>(v);
    }
    [[nodiscard]]
    static Algorithm alg_ml_kem(const MlKemVariant v) noexcept {
        return kAlgMlKemBase | static_cast<Algorithm>(v);
    }

    // -------------------------------------------------------------------------
    // KDF step constants.
    // -------------------------------------------------------------------------
    [[nodiscard]] static constexpr KdfStep kdf_step_secret() noexcept { return kKdfStepSecret; }
    [[nodiscard]] static constexpr KdfStep kdf_step_salt()   noexcept { return kKdfStepSalt; }
    [[nodiscard]] static constexpr KdfStep kdf_step_info()   noexcept { return kKdfStepInfo; }

    // -------------------------------------------------------------------------
    // Key attribute factories.
    // -------------------------------------------------------------------------
    [[nodiscard]]
    static KeyAttributes make_hkdf_derive_attrs(const std::size_t key_size_bits) noexcept {
        return { .type = KeyAttributes::KeyType::Derive, .bits = key_size_bits,
                 .usage = KeyAttributes::Derive, .alg = kAlgHkdf };
    }
    [[nodiscard]]
    static KeyAttributes make_hkdf_expand_derive_attrs(const std::size_t key_size_bits) noexcept {
        return { .type = KeyAttributes::KeyType::Derive, .bits = key_size_bits,
                 .usage = KeyAttributes::Derive, .alg = kAlgHkdfExpand };
    }
    [[nodiscard]]
    static KeyAttributes make_hmac_generate_attrs(const ShaVariant v, const std::size_t key_size_bits) noexcept {
        return { .type = KeyAttributes::KeyType::Hmac, .bits = key_size_bits,
                 .usage = KeyAttributes::Sign, .alg = alg_hmac(v) };
    }
    [[nodiscard]]
    static KeyAttributes make_hmac_verify_attrs(const ShaVariant v, const std::size_t key_size_bits) noexcept {
        return { .type = KeyAttributes::KeyType::Hmac, .bits = key_size_bits,
                 .usage = KeyAttributes::Verify, .alg = alg_hmac(v) };
    }
    [[nodiscard]]
    static KeyAttributes make_ecdsa_generate_attrs(const std::size_t key_bits) noexcept {
        return { .type = KeyAttributes::KeyType::EcKeyPair, .bits = key_bits,
                 .usage = static_cast<uint8_t>(KeyAttributes::Sign | KeyAttributes::Verify | KeyAttributes::Export),
                 .alg = kAlgEcdsa };
    }
    [[nodiscard]]
    static KeyAttributes make_ecdsa_sign_attrs(const std::size_t key_bits) noexcept {
        return { .type = KeyAttributes::KeyType::EcKeyPair, .bits = key_bits,
                 .usage = KeyAttributes::Sign, .alg = kAlgEcdsa };
    }
    [[nodiscard]]
    static KeyAttributes make_ecdsa_verify_attrs(const std::size_t key_bits) noexcept {
        return { .type = KeyAttributes::KeyType::EcPublicKey, .bits = key_bits,
                 .usage = KeyAttributes::Verify, .alg = kAlgEcdsa };
    }
    [[nodiscard]]
    static KeyAttributes make_ecdh_generate_attrs(const std::size_t key_bits) noexcept {
        return { .type = KeyAttributes::KeyType::EcKeyPair, .bits = key_bits,
                 .usage = static_cast<uint8_t>(KeyAttributes::Derive | KeyAttributes::Export),
                 .alg = kAlgEcdh };
    }
    [[nodiscard]]
    static KeyAttributes make_ecdh_agree_attrs(const std::size_t key_bits) noexcept {
        return { .type = KeyAttributes::KeyType::EcKeyPair, .bits = key_bits,
                 .usage = KeyAttributes::Derive, .alg = kAlgEcdh };
    }
    [[nodiscard]]
    static KeyAttributes make_aes256_gcm_encrypt_attrs() noexcept {
        return { .type = KeyAttributes::KeyType::Aes256, .bits = aes256_key_bits,
                 .usage = KeyAttributes::Encrypt, .alg = kAlgAesGcm };
    }
    [[nodiscard]]
    static KeyAttributes make_aes256_gcm_decrypt_attrs() noexcept {
        return { .type = KeyAttributes::KeyType::Aes256, .bits = aes256_key_bits,
                 .usage = KeyAttributes::Decrypt, .alg = kAlgAesGcm };
    }
    [[nodiscard]]
    static KeyAttributes make_chacha20_poly1305_encrypt_attrs() noexcept {
        return { .type = KeyAttributes::KeyType::ChaCha20, .bits = chacha20_key_bits,
                 .usage = KeyAttributes::Encrypt, .alg = kAlgChaCha20Poly };
    }
    [[nodiscard]]
    static KeyAttributes make_chacha20_poly1305_decrypt_attrs() noexcept {
        return { .type = KeyAttributes::KeyType::ChaCha20, .bits = chacha20_key_bits,
                 .usage = KeyAttributes::Decrypt, .alg = kAlgChaCha20Poly };
    }
    [[nodiscard]]
    static KeyAttributes make_rsa_oaep_encrypt_attrs(const std::size_t key_bits) noexcept {
        return { .type = KeyAttributes::KeyType::RsaPublicKey, .bits = key_bits,
                 .usage = KeyAttributes::Encrypt, .alg = kAlgRsaOaep };
    }
    [[nodiscard]]
    static KeyAttributes make_rsa_oaep_decrypt_attrs(const std::size_t key_bits) noexcept {
        return { .type = KeyAttributes::KeyType::RsaKeyPair, .bits = key_bits,
                 .usage = KeyAttributes::Decrypt, .alg = kAlgRsaOaep };
    }
    [[nodiscard]]
    static KeyAttributes make_rsa_pss_sign_attrs(const std::size_t key_bits) noexcept {
        return { .type = KeyAttributes::KeyType::RsaKeyPair, .bits = key_bits,
                 .usage = KeyAttributes::Sign, .alg = kAlgRsaPss };
    }
    [[nodiscard]]
    static KeyAttributes make_rsa_pss_verify_attrs(const std::size_t key_bits) noexcept {
        return { .type = KeyAttributes::KeyType::RsaPublicKey, .bits = key_bits,
                 .usage = KeyAttributes::Verify, .alg = kAlgRsaPss };
    }
    [[nodiscard]]
    static KeyAttributes make_rsa_key_pair_attrs(const std::size_t key_bits) noexcept {
        return { .type = KeyAttributes::KeyType::RsaKeyPair, .bits = key_bits,
                 .usage = static_cast<uint8_t>(KeyAttributes::Encrypt | KeyAttributes::Decrypt |
                                               KeyAttributes::Sign    | KeyAttributes::Verify  |
                                               KeyAttributes::Export),
                 .alg = kAlgRsaOaep };
    }
    [[nodiscard]]
    static KeyAttributes make_slh_dsa_sign_attrs(const SlhDsaVariant v) noexcept {
        return { .type = KeyAttributes::KeyType::SlhDsaKeyPair,
                 .bits = slh_dsa_private_key_size(v) * 8U,
                 .usage = KeyAttributes::Sign, .alg = alg_slh_dsa(v) };
    }
    [[nodiscard]]
    static KeyAttributes make_slh_dsa_verify_attrs(const SlhDsaVariant v) noexcept {
        return { .type = KeyAttributes::KeyType::SlhDsaPublicKey,
                 .bits = slh_dsa_public_key_size(v) * 8U,
                 .usage = KeyAttributes::Verify, .alg = alg_slh_dsa(v) };
    }
    [[nodiscard]]
    static KeyAttributes make_slh_dsa_generate_attrs(const SlhDsaVariant v) noexcept {
        return { .type = KeyAttributes::KeyType::SlhDsaKeyPair,
                 .bits = slh_dsa_private_key_size(v) * 8U,
                 .usage = static_cast<uint8_t>(KeyAttributes::Sign | KeyAttributes::Export),
                 .alg = alg_slh_dsa(v) };
    }
    [[nodiscard]]
    static KeyAttributes make_ml_dsa_sign_attrs(const MlDsaVariant v) noexcept {
        return { .type = KeyAttributes::KeyType::MlDsaKeyPair,
                 .bits = ml_dsa_private_key_size(v) * 8U,
                 .usage = KeyAttributes::Sign, .alg = alg_ml_dsa(v) };
    }
    [[nodiscard]]
    static KeyAttributes make_ml_dsa_verify_attrs(const MlDsaVariant v) noexcept {
        return { .type = KeyAttributes::KeyType::MlDsaPublicKey,
                 .bits = ml_dsa_public_key_size(v) * 8U,
                 .usage = KeyAttributes::Verify, .alg = alg_ml_dsa(v) };
    }
    [[nodiscard]]
    static KeyAttributes make_ml_dsa_generate_attrs(const MlDsaVariant v) noexcept {
        return { .type = KeyAttributes::KeyType::MlDsaKeyPair,
                 .bits = ml_dsa_private_key_size(v) * 8U,
                 .usage = static_cast<uint8_t>(KeyAttributes::Sign | KeyAttributes::Export),
                 .alg = alg_ml_dsa(v) };
    }
    [[nodiscard]]
    static KeyAttributes make_ml_kem_generate_attrs(const MlKemVariant v) noexcept {
        return { .type = KeyAttributes::KeyType::MlKemKeyPair,
                 .bits = ml_kem_private_key_size(v) * 8U,
                 .usage = static_cast<uint8_t>(KeyAttributes::Decrypt | KeyAttributes::Export),
                 .alg = alg_ml_kem(v) };
    }
    [[nodiscard]]
    static KeyAttributes make_ml_kem_encap_attrs(const MlKemVariant v) noexcept {
        return { .type = KeyAttributes::KeyType::MlKemPublicKey,
                 .bits = ml_kem_public_key_size(v) * 8U,
                 .usage = KeyAttributes::Encrypt, .alg = alg_ml_kem(v) };
    }
    [[nodiscard]]
    static KeyAttributes make_ml_kem_decap_attrs(const MlKemVariant v) noexcept {
        return { .type = KeyAttributes::KeyType::MlKemKeyPair,
                 .bits = ml_kem_private_key_size(v) * 8U,
                 .usage = KeyAttributes::Decrypt, .alg = alg_ml_kem(v) };
    }

    // -------------------------------------------------------------------------
    // Output size helpers — hard-coded formulas matching OpenSSL behaviour.
    // -------------------------------------------------------------------------
    [[nodiscard]]
    static std::size_t ecdsa_sign_output_size(const std::size_t key_bits) noexcept {
        // DER-encoded ECDSA signature: 2 * ceil(key_bits/8) + 8 bytes overhead.
        const std::size_t coord = (key_bits + 7U) / 8U;
        return 2U * coord + 8U;
    }
    [[nodiscard]]
    static std::size_t ecdh_shared_secret_size(const std::size_t key_bits) noexcept {
        return (key_bits + 7U) / 8U;
    }
    [[nodiscard]]
    static std::size_t ec_private_key_export_size(const std::size_t key_bits) noexcept {
        return (key_bits + 7U) / 8U;
    }
    [[nodiscard]]
    static std::size_t ec_public_key_export_size(const std::size_t key_bits) noexcept {
        // Uncompressed point: 0x04 + 2 * coord_bytes
        return 1U + 2U * ((key_bits + 7U) / 8U);
    }
    [[nodiscard]]
    static std::size_t aes_gcm_encrypt_output_size(const std::size_t plaintext_size) noexcept {
        return plaintext_size <= SIZE_MAX - 16U ? plaintext_size + 16U : 0U;  // + 128-bit GCM tag
    }
    [[nodiscard]]
    static std::size_t aes_gcm_decrypt_output_size(const std::size_t ciphertext_size) noexcept {
        return ciphertext_size > 16U ? ciphertext_size - 16U : 0U;
    }
    [[nodiscard]]
    static std::size_t chacha20_encrypt_output_size(const std::size_t plaintext_size) noexcept {
        return plaintext_size <= SIZE_MAX - 16U ? plaintext_size + 16U : 0U;  // + 128-bit Poly1305 tag
    }
    [[nodiscard]]
    static std::size_t chacha20_decrypt_output_size(const std::size_t ciphertext_size) noexcept {
        return ciphertext_size > 16U ? ciphertext_size - 16U : 0U;
    }
    [[nodiscard]]
    static std::size_t rsa_oaep_encrypt_output_size(const std::size_t key_bits) noexcept {
        return key_bits / 8U;
    }
    [[nodiscard]]
    static std::size_t rsa_oaep_decrypt_output_size(const std::size_t key_bits) noexcept {
        return key_bits / 8U;
    }
    [[nodiscard]]
    static std::size_t rsa_pss_sign_output_size(const std::size_t key_bits) noexcept {
        return key_bits / 8U;
    }
    [[nodiscard]]
    static std::size_t rsa_private_key_export_size(const std::size_t key_bits) noexcept {
        // PKCS#1 DER: ~5 * (key_bits/8) + overhead.  Use a generous bound.
        return 5U * (key_bits / 8U) + 64U;
    }
    [[nodiscard]]
    static std::size_t rsa_public_key_export_size(const std::size_t key_bits) noexcept {
        // SubjectPublicKeyInfo DER: key_bits/8 + ~50 bytes overhead.
        return key_bits / 8U + 50U;
    }
    [[nodiscard]]
    static std::size_t slh_dsa_sign_output_size(const SlhDsaVariant v) noexcept {
        return slh_dsa_signature_size(v);
    }
    [[nodiscard]]
    static std::size_t slh_dsa_private_key_export_size(const SlhDsaVariant v) noexcept {
        return slh_dsa_private_key_size(v);
    }
    [[nodiscard]]
    static std::size_t slh_dsa_public_key_export_size(const SlhDsaVariant v) noexcept {
        return slh_dsa_public_key_size(v);
    }
    [[nodiscard]]
    static std::size_t ml_dsa_sign_output_size(const MlDsaVariant v) noexcept {
        return ml_dsa_signature_size(v);
    }
    [[nodiscard]]
    static std::size_t ml_dsa_private_key_export_size(const MlDsaVariant v) noexcept {
        return ml_dsa_private_key_size(v);
    }
    [[nodiscard]]
    static std::size_t ml_dsa_public_key_export_size(const MlDsaVariant v) noexcept {
        return ml_dsa_public_key_size(v);
    }
    [[nodiscard]]
    static std::size_t ml_kem_ciphertext_size(const MlKemVariant v) noexcept {
        return ::ml_kem_ciphertext_size(v);
    }
    [[nodiscard]]
    static std::size_t ml_kem_shared_secret_size(const MlKemVariant v) noexcept {
        return ::ml_kem_shared_secret_size(v);
    }
    [[nodiscard]]
    static std::size_t ml_kem_private_key_export_size(const MlKemVariant v) noexcept {
        return ml_kem_private_key_size(v);
    }
    [[nodiscard]]
    static std::size_t ml_kem_public_key_export_size(const MlKemVariant v) noexcept {
        return ml_kem_public_key_size(v);
    }

    // -------------------------------------------------------------------------
    // Internal helpers.
    // -------------------------------------------------------------------------

    // Returns the OpenSSL digest name string for a hash Algorithm tag, or
    // nullptr if the tag is not a recognised hash algorithm.
    [[nodiscard]]
    static constexpr const char* digest_name(const Algorithm alg) noexcept {
        switch (alg) {
            case kAlgSha256:   return "SHA2-256";
            case kAlgSha384:   return "SHA2-384";
            case kAlgSha512:   return "SHA2-512";
            case kAlgSha3_256: return "SHA3-256";
            case kAlgSha3_384: return "SHA3-384";
            case kAlgSha3_512: return "SHA3-512";
            default:           return nullptr;
        }
    }

    // Returns the OpenSSL algorithm name string for a SlhDsaVariant, or nullptr.
    [[nodiscard]]
    static constexpr const char* slh_dsa_alg_name(const SlhDsaVariant v) noexcept {
        switch (v) {
            case SlhDsaVariant::Sha2_128s: return "SLH-DSA-SHA2-128s";
            case SlhDsaVariant::Sha2_128f: return "SLH-DSA-SHA2-128f";
            case SlhDsaVariant::Sha2_192s: return "SLH-DSA-SHA2-192s";
            case SlhDsaVariant::Sha2_192f: return "SLH-DSA-SHA2-192f";
            case SlhDsaVariant::Sha2_256s: return "SLH-DSA-SHA2-256s";
            case SlhDsaVariant::Sha2_256f: return "SLH-DSA-SHA2-256f";
        }
    }

    // Extracts the SlhDsaVariant from an Algorithm tag, or returns nullopt.
    [[nodiscard]]
    static constexpr const char* slh_dsa_name_from_alg(const Algorithm alg) noexcept {
        if ((alg & 0xFF'000000U) != kAlgSlhDsaBase) { return nullptr; }
        const auto v = static_cast<SlhDsaVariant>(alg & 0xFFU);
        return slh_dsa_alg_name(v);
    }

    // Returns the OpenSSL algorithm name string for a MlDsaVariant, or nullptr.
    [[nodiscard]]
    static constexpr const char* ml_dsa_alg_name(const MlDsaVariant v) noexcept {
        switch (v) {
            case MlDsaVariant::Dsa44: return "ML-DSA-44";
            case MlDsaVariant::Dsa65: return "ML-DSA-65";
            case MlDsaVariant::Dsa87: return "ML-DSA-87";
        }
    }

    // Extracts the MlDsaVariant from an Algorithm tag, or returns nullptr.
    [[nodiscard]]
    static constexpr const char* ml_dsa_name_from_alg(const Algorithm alg) noexcept {
        if ((alg & 0xFF'000000U) != kAlgMlDsaBase) { return nullptr; }
        const auto v = static_cast<MlDsaVariant>(alg & 0xFFU);
        return ml_dsa_alg_name(v);
    }

    // Returns the OpenSSL algorithm name string for a MlKemVariant, or nullptr.
    [[nodiscard]]
    static constexpr const char* ml_kem_alg_name(const MlKemVariant v) noexcept {
        switch (v) {
            case MlKemVariant::Kem512:  return "ML-KEM-512";
            case MlKemVariant::Kem768:  return "ML-KEM-768";
            case MlKemVariant::Kem1024: return "ML-KEM-1024";
        }
    }

    // Extracts the MlKemVariant from an Algorithm tag, or returns nullptr.
    [[nodiscard]]
    static constexpr const char* ml_kem_name_from_alg(const Algorithm alg) noexcept {
        if ((alg & 0xFF'000000U) != kAlgMlKemBase) { return nullptr; }
        const auto v = static_cast<MlKemVariant>(alg & 0xFFU);
        return ml_kem_alg_name(v);
    }

    // Returns the OBJ_txt2nid curve name for a key_bits value, or nullptr.
    [[nodiscard]]
    static constexpr const char* ec_curve_name(const std::size_t key_bits) noexcept {
        switch (key_bits) {
            case 256U: return "P-256";
            case 384U: return "P-384";
            case 521U: return "P-521";
            default:   return nullptr;
        }
    }

    // Returns the EVP_CIPHER* for an AEAD Algorithm tag, or nullptr.
    [[nodiscard]]
    static const EVP_CIPHER* aead_cipher(const Algorithm alg) noexcept {
        switch (alg) {
            case kAlgAesGcm:       return EVP_aes_256_gcm();
            case kAlgChaCha20Poly: return EVP_chacha20_poly1305();
            default:               return nullptr;
        }
    }

    // Returns the underlying digest name for an HMAC Algorithm tag, or nullptr.
    [[nodiscard]]
    static constexpr const char* hmac_digest_name(const Algorithm alg) noexcept {
        switch (alg) {
            case kAlgHmacSha256:   return "SHA2-256";
            case kAlgHmacSha384:   return "SHA2-384";
            case kAlgHmacSha512:   return "SHA2-512";
            case kAlgHmacSha3_256: return "SHA3-256";
            case kAlgHmacSha3_384: return "SHA3-384";
            case kAlgHmacSha3_512: return "SHA3-512";
            default:               return nullptr;
        }
    }

    // -------------------------------------------------------------------------
    // Low-level crypto operations.
    // -------------------------------------------------------------------------

    [[nodiscard]]
    static Status crypto_init() noexcept {
        // OpenSSL 3.x auto-initialises; nothing required here.
        return ok;
    }

    [[nodiscard]]
    static Status generate_random(CryptoByte* output, const std::size_t output_size) noexcept {
        return RAND_bytes(output, static_cast<int>(output_size)) == 1 ? ok : err_invalid_arg;
    }

    [[nodiscard]]
    static Status import_key(
        const KeyAttributes* attributes,
        const CryptoByte* data, const std::size_t data_length,
        KeyId* key) noexcept
    {
        using namespace openssl_provider::detail;
        if (attributes == nullptr || data == nullptr || key == nullptr) { return err_invalid_arg; }

        OpenSslKeyKind kind = OpenSslKeyKind::None;
        switch (attributes->type) {
            case KeyAttributes::KeyType::Aes256:   kind = OpenSslKeyKind::Aes256;   break;
            case KeyAttributes::KeyType::ChaCha20: kind = OpenSslKeyKind::ChaCha20; break;
            case KeyAttributes::KeyType::Hmac:     kind = OpenSslKeyKind::Hmac;     break;
            case KeyAttributes::KeyType::Derive:   kind = OpenSslKeyKind::Derive;   break;
            case KeyAttributes::KeyType::EcKeyPair: {
                // data = raw big-endian private scalar (key_bits/8 bytes).
                const char* curve = ec_curve_name(attributes->bits);
                if (curve == nullptr) { return err_invalid_arg; }
                OSSL_PARAM params[] = {  // NOLINT(*)
                    OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                        const_cast<char*>(curve), 0),  // NOLINT(cppcoreguidelines-pro-type-const-cast)
                    OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_PRIV_KEY,
                        const_cast<CryptoByte*>(data), data_length),  // NOLINT(cppcoreguidelines-pro-type-const-cast)
                    OSSL_PARAM_END
                };
                EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
                if (pctx == nullptr) { return err_invalid_arg; }
                EVP_PKEY* pkey = nullptr;
                const Status rv_import = (EVP_PKEY_fromdata_init(pctx) == ok &&
                    EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_KEYPAIR, params) == ok)
                    ? ok : err_invalid_arg;
                EVP_PKEY_CTX_free(pctx);
                if (rv_import != ok || pkey == nullptr) { return err_invalid_arg; }
                const unsigned int id = ossl_asym_store_import(pkey, attributes->alg);
                if (id == 0U) { EVP_PKEY_free(pkey); return err_invalid_arg; }
                *key = id;
                return ok;
            }
            case KeyAttributes::KeyType::EcPublicKey: {
                // data = uncompressed point: 0x04 || x || y.
                const char* curve = ec_curve_name(attributes->bits);
                if (curve == nullptr) { return err_invalid_arg; }
                OSSL_PARAM params[] = {  // NOLINT(*)
                    OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                        const_cast<char*>(curve), 0),  // NOLINT(cppcoreguidelines-pro-type-const-cast)
                    OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                        const_cast<CryptoByte*>(data), data_length),  // NOLINT(cppcoreguidelines-pro-type-const-cast)
                    OSSL_PARAM_END
                };
                EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
                if (pctx == nullptr) { return err_invalid_arg; }
                EVP_PKEY* pkey = nullptr;
                const Status rv_import = (EVP_PKEY_fromdata_init(pctx) == ok &&
                    EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) == ok)
                    ? ok : err_invalid_arg;
                EVP_PKEY_CTX_free(pctx);
                if (rv_import != ok || pkey == nullptr) { return err_invalid_arg; }
                const unsigned int id = ossl_asym_store_import(pkey, attributes->alg);
                if (id == 0U) { EVP_PKEY_free(pkey); return err_invalid_arg; }
                *key = id;
                return ok;
            }
            case KeyAttributes::KeyType::RsaKeyPair: {
                // Private key in PKCS#1 DER format (from i2d_PrivateKey).
                const CryptoByte* p = data;
                EVP_PKEY* pkey = d2i_PrivateKey(EVP_PKEY_RSA, nullptr, &p, static_cast<long>(data_length));
                if (pkey == nullptr) { return err_invalid_arg; }
                const unsigned int id = ossl_asym_store_import(pkey, attributes->alg);
                if (id == 0U) { EVP_PKEY_free(pkey); return err_invalid_arg; }
                *key = id;
                return ok;
            }
            case KeyAttributes::KeyType::RsaPublicKey: {
                // Public key in SubjectPublicKeyInfo DER format (from i2d_PublicKey).
                const CryptoByte* p = data;
                EVP_PKEY* pkey = d2i_PublicKey(EVP_PKEY_RSA, nullptr, &p, static_cast<long>(data_length));
                if (pkey == nullptr) { return err_invalid_arg; }
                const unsigned int id = ossl_asym_store_import(pkey, attributes->alg);
                if (id == 0U) { EVP_PKEY_free(pkey); return err_invalid_arg; }
                *key = id;
                return ok;
            }
            case KeyAttributes::KeyType::SlhDsaKeyPair: {
                // Raw private key bytes directly (FIPS 205 format).
                const char* alg_name = slh_dsa_name_from_alg(attributes->alg);
                if (alg_name == nullptr) { return err_invalid_arg; }
                EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key_ex(
                    nullptr, alg_name, nullptr, data, data_length);
                if (pkey == nullptr) { return err_invalid_arg; }
                const unsigned int id = ossl_asym_store_import(pkey, attributes->alg);
                if (id == 0U) { EVP_PKEY_free(pkey); return err_invalid_arg; }
                *key = id;
                return ok;
            }
            case KeyAttributes::KeyType::SlhDsaPublicKey: {
                // Raw public key bytes directly (FIPS 205 format).
                const char* alg_name = slh_dsa_name_from_alg(attributes->alg);
                if (alg_name == nullptr) { return err_invalid_arg; }
                EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key_ex(
                    nullptr, alg_name, nullptr, data, data_length);
                if (pkey == nullptr) { return err_invalid_arg; }
                const unsigned int id = ossl_asym_store_import(pkey, attributes->alg);
                if (id == 0U) { EVP_PKEY_free(pkey); return err_invalid_arg; }
                *key = id;
                return ok;
            }
            case KeyAttributes::KeyType::MlDsaKeyPair: {
                // Raw private key bytes directly (FIPS 204 format).
                const char* alg_name = ml_dsa_name_from_alg(attributes->alg);
                if (alg_name == nullptr) { return err_invalid_arg; }
                EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key_ex(
                    nullptr, alg_name, nullptr, data, data_length);
                if (pkey == nullptr) { return err_invalid_arg; }
                const unsigned int id = ossl_asym_store_import(pkey, attributes->alg);
                if (id == 0U) { EVP_PKEY_free(pkey); return err_invalid_arg; }
                *key = id;
                return ok;
            }
            case KeyAttributes::KeyType::MlDsaPublicKey: {
                // Raw public key bytes directly (FIPS 204 format).
                const char* alg_name = ml_dsa_name_from_alg(attributes->alg);
                if (alg_name == nullptr) { return err_invalid_arg; }
                EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key_ex(
                    nullptr, alg_name, nullptr, data, data_length);
                if (pkey == nullptr) { return err_invalid_arg; }
                const unsigned int id = ossl_asym_store_import(pkey, attributes->alg);
                if (id == 0U) { EVP_PKEY_free(pkey); return err_invalid_arg; }
                *key = id;
                return ok;
            }
            case KeyAttributes::KeyType::MlKemKeyPair: {
                // Raw private key bytes directly (FIPS 203 format).
                const char* alg_name = ml_kem_name_from_alg(attributes->alg);
                if (alg_name == nullptr) { return err_invalid_arg; }
                EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key_ex(
                    nullptr, alg_name, nullptr, data, data_length);
                if (pkey == nullptr) { return err_invalid_arg; }
                const unsigned int id = ossl_asym_store_import(pkey, attributes->alg);
                if (id == 0U) { EVP_PKEY_free(pkey); return err_invalid_arg; }
                *key = id;
                return ok;
            }
            case KeyAttributes::KeyType::MlKemPublicKey: {
                // Raw public key bytes directly (FIPS 203 format).
                const char* alg_name = ml_kem_name_from_alg(attributes->alg);
                if (alg_name == nullptr) { return err_invalid_arg; }
                EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key_ex(
                    nullptr, alg_name, nullptr, data, data_length);
                if (pkey == nullptr) { return err_invalid_arg; }
                const unsigned int id = ossl_asym_store_import(pkey, attributes->alg);
                if (id == 0U) { EVP_PKEY_free(pkey); return err_invalid_arg; }
                *key = id;
                return ok;
            }
            default: return err_invalid_arg;
        }

        const unsigned int id = ossl_raw_store_import(kind, data, data_length);
        if (id == 0U) { return err_invalid_arg; }
        *key = id;
        return ok;
    }

    [[nodiscard]]
    static Status generate_key(
        const KeyAttributes* attributes,
        KeyId* key) noexcept
    {
        using namespace openssl_provider::detail;
        if (attributes == nullptr || key == nullptr) { return err_invalid_arg; }

        if (attributes->type == KeyAttributes::KeyType::EcKeyPair) {
            const char* curve = ec_curve_name(attributes->bits);
            if (curve == nullptr) { return err_invalid_arg; }
            EVP_PKEY* pkey = EVP_EC_gen(curve);
            if (pkey == nullptr) { return err_invalid_arg; }
            const unsigned int id = ossl_asym_store_import(pkey, attributes->alg);
            if (id == 0U) { EVP_PKEY_free(pkey); return err_invalid_arg; }
            *key = id;
            return ok;
        }

        if (attributes->type == KeyAttributes::KeyType::RsaKeyPair) {
            EVP_PKEY* pkey = EVP_RSA_gen(static_cast<unsigned int>(attributes->bits));
            if (pkey == nullptr) { return err_invalid_arg; }
            const unsigned int id = ossl_asym_store_import(pkey, attributes->alg);
            if (id == 0U) { EVP_PKEY_free(pkey); return err_invalid_arg; }
            *key = id;
            return ok;
        }

        if (attributes->type == KeyAttributes::KeyType::SlhDsaKeyPair) {
            const char* alg_name = slh_dsa_name_from_alg(attributes->alg);
            if (alg_name == nullptr) { return err_invalid_arg; }
            EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_from_name(nullptr, alg_name, nullptr);
            if (pctx == nullptr) { return err_invalid_arg; }
            EVP_PKEY* pkey = nullptr;
            const Status rv_gen = (EVP_PKEY_keygen_init(pctx) == ok &&
                EVP_PKEY_generate(pctx, &pkey) == ok)
                ? ok : err_invalid_arg;
            EVP_PKEY_CTX_free(pctx);
            if (rv_gen != ok || pkey == nullptr) { return err_invalid_arg; }
            const unsigned int id = ossl_asym_store_import(pkey, attributes->alg);
            if (id == 0U) { EVP_PKEY_free(pkey); return err_invalid_arg; }
            *key = id;
            return ok;
        }

        if (attributes->type == KeyAttributes::KeyType::MlDsaKeyPair) {
            const char* alg_name = ml_dsa_name_from_alg(attributes->alg);
            if (alg_name == nullptr) { return err_invalid_arg; }
            EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_from_name(nullptr, alg_name, nullptr);
            if (pctx == nullptr) { return err_invalid_arg; }
            EVP_PKEY* pkey = nullptr;
            const Status rv_gen = (EVP_PKEY_keygen_init(pctx) == ok &&
                EVP_PKEY_generate(pctx, &pkey) == ok)
                ? ok : err_invalid_arg;
            EVP_PKEY_CTX_free(pctx);
            if (rv_gen != ok || pkey == nullptr) { return err_invalid_arg; }
            const unsigned int id = ossl_asym_store_import(pkey, attributes->alg);
            if (id == 0U) { EVP_PKEY_free(pkey); return err_invalid_arg; }
            *key = id;
            return ok;
        }

        if (attributes->type == KeyAttributes::KeyType::MlKemKeyPair) {
            const char* alg_name = ml_kem_name_from_alg(attributes->alg);
            if (alg_name == nullptr) { return err_invalid_arg; }
            EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_from_name(nullptr, alg_name, nullptr);
            if (pctx == nullptr) { return err_invalid_arg; }
            EVP_PKEY* pkey = nullptr;
            const Status rv_gen = (EVP_PKEY_keygen_init(pctx) == ok &&
                EVP_PKEY_generate(pctx, &pkey) == ok)
                ? ok : err_invalid_arg;
            EVP_PKEY_CTX_free(pctx);
            if (rv_gen != ok || pkey == nullptr) { return err_invalid_arg; }
            const unsigned int id = ossl_asym_store_import(pkey, attributes->alg);
            if (id == 0U) { EVP_PKEY_free(pkey); return err_invalid_arg; }
            *key = id;
            return ok;
        }

        return err_invalid_arg;
    }

    [[nodiscard]]
    static Status destroy_key(const KeyId key) noexcept {
        using namespace openssl_provider::detail;
        if (ossl_asym_id_valid(key)) {
            ossl_asym_store_destroy(key);
            return ok;
        }
        if (ossl_raw_id_valid(key)) {
            ossl_raw_store_destroy(key);
            return ok;
        }
        return err_invalid_arg;
    }

    [[nodiscard]]
    static Status export_key(
        const KeyId key,
        CryptoByte* data, const std::size_t data_size, std::size_t* data_length) noexcept
    {
        using namespace openssl_provider::detail;
        EVP_PKEY* pkey = ossl_asym_store_get(key); // NOLINT(misc-const-correctness)
        if (pkey == nullptr) { return err_invalid_arg; }

        if (EVP_PKEY_is_a(pkey, "RSA") == 1) {
            // Export PKCS#1 DER private key.
            CryptoByte* p = data;
            const int len = i2d_PrivateKey(pkey, &p);
            if (len < 0 || static_cast<std::size_t>(len) > data_size) { return err_invalid_arg; }
            *data_length = static_cast<std::size_t>(len);
            return ok;
        }

        // SLH-DSA: export raw private key bytes via EVP_PKEY_get_raw_private_key.
        {
            std::size_t len = 0;
            if (EVP_PKEY_get_raw_private_key(pkey, nullptr, &len) == ok && len > 0) {
                if (len > data_size) { return err_invalid_arg; }
                if (EVP_PKEY_get_raw_private_key(pkey, data, &len) != ok) { return err_invalid_arg; }
                *data_length = len;
                return ok;
            }
        }

        // EC: export raw private scalar, native-endian so OSSL_PARAM_construct_BN round-trips.
        BIGNUM* bn = nullptr;
        if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &bn) != ok || bn == nullptr) {
            return err_invalid_arg;
        }
        const int nbytes = BN_num_bytes(bn);
        if (nbytes < 0 || static_cast<std::size_t>(nbytes) > data_size) {
            BN_free(bn);
            return err_invalid_arg;
        }
        // BN_bn2nativepad produces native-endian output (LE on ARM, BE on x86).
        const int written = BN_bn2nativepad(bn, data, static_cast<int>(data_size));
        BN_free(bn);
        if (written < 0) { return err_invalid_arg; }
        *data_length = static_cast<std::size_t>(written);
        return ok;
    }

    [[nodiscard]]
    static Status export_public_key(
        const KeyId key,
        CryptoByte* data, const std::size_t data_size, std::size_t* data_length) noexcept
    {
        using namespace openssl_provider::detail;
        EVP_PKEY* pkey = ossl_asym_store_get(key); // NOLINT(misc-const-correctness)
        if (pkey == nullptr) { return err_invalid_arg; }

        if (EVP_PKEY_is_a(pkey, "RSA") == 1) {
            // Export SubjectPublicKeyInfo DER.
            CryptoByte* p = data;
            const int len = i2d_PublicKey(pkey, &p);
            if (len < 0 || static_cast<std::size_t>(len) > data_size) { return err_invalid_arg; }
            *data_length = static_cast<std::size_t>(len);
            return ok;
        }

        // SLH-DSA: export raw public key bytes.
        {
            std::size_t len = 0;
            if (EVP_PKEY_get_raw_public_key(pkey, nullptr, &len) == ok && len > 0) {
                if (len > data_size) { return err_invalid_arg; }
                if (EVP_PKEY_get_raw_public_key(pkey, data, &len) != ok) { return err_invalid_arg; }
                *data_length = len;
                return ok;
            }
        }

        // EC: export uncompressed point (04 || x || y).
        std::size_t len = data_size;
        if (EVP_PKEY_get_octet_string_param(pkey,
                OSSL_PKEY_PARAM_PUB_KEY, data, data_size, &len) != ok) {
            return err_invalid_arg;
        }
        *data_length = len;
        return ok;
    }

    [[nodiscard]]
    static Status hash_compute(
        const Algorithm alg,
        const CryptoByte* input, const std::size_t input_length,
        CryptoByte* hash, const std::size_t hash_size, std::size_t* hash_length) noexcept
    {
        const char* name = digest_name(alg);
        if (name == nullptr) { return err_invalid_arg; }
        std::size_t len = hash_size;
        const Status rv = EVP_Q_digest(nullptr, name, nullptr,
                                       input, input_length,
                                       hash, &len);
        if (rv != ok) { return err_invalid_arg; }
        *hash_length = len;
        return ok;
    }

    [[nodiscard]]
    static Status mac_compute(  // NOLINT(readability-function-size)
        const KeyId key, const Algorithm alg,
        const CryptoByte* input, const std::size_t input_length,
        CryptoByte* mac, const std::size_t mac_size, std::size_t* mac_length) noexcept
    {
        using namespace openssl_provider::detail;
        const char* digest = hmac_digest_name(alg);
        if (digest == nullptr) { return err_invalid_arg; }

        const OpenSslRawSlot* slot = ossl_raw_store_get(key);
        if (slot == nullptr) { return err_invalid_arg; }

        // Build the digest parameter for EVP_Q_mac.
        OSSL_PARAM params[] = {  // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
            OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_DIGEST,
                                   const_cast<char*>(digest),  // NOLINT(cppcoreguidelines-pro-type-const-cast)
                                   0),
            OSSL_PARAM_END
        };

        std::size_t out_len = mac_size;
        const unsigned char* result = EVP_Q_mac(nullptr, "HMAC", nullptr,
                                                digest, params,
                                                slot->data.data(), slot->len,
                                                input, input_length,
                                                mac, mac_size, &out_len);
        if (result == nullptr) { return err_invalid_arg; }
        *mac_length = out_len;
        return ok;
    }

    [[nodiscard]]
    static Status mac_verify(
        const KeyId key, const Algorithm alg,
        const CryptoByte* input, const std::size_t input_length,
        const CryptoByte* mac, const std::size_t mac_length) noexcept
    {
        // Compute a fresh MAC and compare in constant time.
        std::array<CryptoByte, 64> computed{};  // large enough for any HMAC output
        std::size_t computed_len = 0;
        const Status rv = mac_compute(key, alg,
                                      input, input_length,
                                      computed.data(), computed.size(),
                                      &computed_len);
        if (rv != ok) { return err_invalid_arg; }
        if (computed_len != mac_length) { return err_invalid_sig; }
        // CRYPTO_memcmp is OpenSSL's constant-time compare.
        return CRYPTO_memcmp(computed.data(), mac, mac_length) == 0 ? ok : err_invalid_sig;
    }

    [[nodiscard]]
    static Status aead_encrypt(  // NOLINT(readability-function-size)
        const KeyId key, const Algorithm alg,
        const CryptoByte* nonce, const std::size_t nonce_length,
        const CryptoByte* additional_data, const std::size_t additional_data_length,
        const CryptoByte* plaintext, const std::size_t plaintext_length,
        CryptoByte* ciphertext, const std::size_t ciphertext_size,
        std::size_t* ciphertext_length) noexcept
    {
        using namespace openssl_provider::detail;
        constexpr std::size_t tag_len = 16U;
        constexpr std::size_t aead_nonce_len = 12U;
        if (nonce_length != aead_nonce_len) { return err_invalid_arg; }
        if (plaintext_length > SIZE_MAX - tag_len) { return err_invalid_arg; }
        if (ciphertext_size < plaintext_length + tag_len) { return err_invalid_arg; }

        const EVP_CIPHER* cipher = aead_cipher(alg);
        if (cipher == nullptr) { return err_invalid_arg; }

        const OpenSslRawSlot* slot = ossl_raw_store_get(key);
        if (slot == nullptr) { return err_invalid_arg; }

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (ctx == nullptr) { return err_invalid_arg; }

        Status rv = err_invalid_arg;
        do {
            if (EVP_EncryptInit_ex2(ctx, cipher, slot->data.data(), nonce, nullptr) != ok) { break; }
            int out_len = 0;
            if (additional_data_length > 0) {
                if (EVP_EncryptUpdate(ctx, nullptr, &out_len,
                                      additional_data,
                                      static_cast<int>(additional_data_length)) != ok) { break; }
            }
            if (EVP_EncryptUpdate(ctx, ciphertext, &out_len,
                                  plaintext, static_cast<int>(plaintext_length)) != ok) { break; }
            std::size_t written = static_cast<std::size_t>(out_len);
            int final_len = 0;
            if (EVP_EncryptFinal_ex(ctx, ciphertext + written, &final_len) != ok) { break; }  // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
            written += static_cast<std::size_t>(final_len);
            // Append the authentication tag.
            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG,
                                    static_cast<int>(tag_len),
                                    ciphertext + written) != ok) { break; }  // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
            *ciphertext_length = written + tag_len;
            rv = ok;
        } while (false);

        EVP_CIPHER_CTX_free(ctx);
        return rv;
    }

    [[nodiscard]]
    static Status aead_decrypt(  // NOLINT(readability-function-size)
        const KeyId key, const Algorithm alg,
        const CryptoByte* nonce, const std::size_t nonce_length,
        const CryptoByte* additional_data, const std::size_t additional_data_length,
        const CryptoByte* ciphertext, const std::size_t ciphertext_length,
        CryptoByte* plaintext, const std::size_t plaintext_size,
        std::size_t* plaintext_length) noexcept
    {
        using namespace openssl_provider::detail;
        constexpr std::size_t tag_len = 16U;
        constexpr std::size_t aead_nonce_len = 12U;
        if (nonce_length != aead_nonce_len) { return err_invalid_arg; }
        if (ciphertext_length < tag_len) { return err_invalid_arg; }
        const std::size_t ct_len = ciphertext_length - tag_len;
        if (plaintext_size < ct_len) { return err_invalid_arg; }

        const EVP_CIPHER* cipher = aead_cipher(alg);
        if (cipher == nullptr) { return err_invalid_arg; }

        const OpenSslRawSlot* slot = ossl_raw_store_get(key);
        if (slot == nullptr) { return err_invalid_arg; }

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (ctx == nullptr) { return err_invalid_arg; }

        Status rv = err_invalid_sig;  // auth failure by default
        do {
            if (EVP_DecryptInit_ex2(ctx, cipher, slot->data.data(), nonce, nullptr) != ok) {
                rv = err_invalid_arg; break;
            }
            // Set the expected tag before finalising.
            // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic,cppcoreguidelines-pro-type-const-cast)
            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
                                    static_cast<int>(tag_len),
                                    const_cast<CryptoByte*>(ciphertext + ct_len)) != ok) {
                rv = err_invalid_arg; break;
            }
            int out_len = 0;
            if (additional_data_length > 0) {
                if (EVP_DecryptUpdate(ctx, nullptr, &out_len,
                                      additional_data,
                                      static_cast<int>(additional_data_length)) != ok) { break; }
            }
            if (EVP_DecryptUpdate(ctx, plaintext, &out_len,
                                  ciphertext, static_cast<int>(ct_len)) != ok) { break; }
            const std::size_t written = static_cast<std::size_t>(out_len);
            int final_len = 0;
            // EVP_DecryptFinal_ex returns 0 if tag verification fails.
            if (EVP_DecryptFinal_ex(ctx, plaintext + written, &final_len) != ok) { break; }  // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
            *plaintext_length = written + static_cast<std::size_t>(final_len);
            rv = ok;
        } while (false);

        EVP_CIPHER_CTX_free(ctx);
        return rv;
    }

    [[nodiscard]]
    static Status sign_message(  // NOLINT(readability-function-size)
        const KeyId key, const Algorithm alg,
        const CryptoByte* input, const std::size_t input_length,
        CryptoByte* signature, const std::size_t signature_size,
        std::size_t* signature_length) noexcept
    {
        using namespace openssl_provider::detail;
        const bool is_pqc = ((alg & 0xFF'000000U) == kAlgSlhDsaBase) ||
                            ((alg & 0xFF'000000U) == kAlgMlDsaBase);
        if (alg != kAlgEcdsa && alg != kAlgRsaPss && !is_pqc) { return err_invalid_arg; }
        EVP_PKEY* pkey = ossl_asym_store_get(key);
        if (pkey == nullptr) { return err_invalid_arg; }
        if (is_pqc && ossl_asym_store_alg(key) != alg) { return err_invalid_arg; }

        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (ctx == nullptr) { return err_invalid_arg; }

        Status rv = err_invalid_arg;
        do {
            EVP_PKEY_CTX* pctx = nullptr;
            // SLH-DSA and ML-DSA use NULL digest (pure-message schemes, no external hash).
            const char* digest = is_pqc ? nullptr : "SHA2-384";
            if (EVP_DigestSignInit_ex(ctx, &pctx, digest,
                                      nullptr, nullptr, pkey, nullptr) != ok) { break; }
            if (alg == kAlgRsaPss) {
                if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) != ok) { break; }
                if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) != ok) { break; }
            }
            std::size_t len = signature_size;
            if (EVP_DigestSign(ctx, signature, &len, input, input_length) != ok) { break; }
            *signature_length = len;
            rv = ok;
        } while (false);

        EVP_MD_CTX_free(ctx);
        return rv;
    }

    [[nodiscard]]
    static Status verify_message(
        const KeyId key, const Algorithm alg,
        const CryptoByte* input, const std::size_t input_length,
        const CryptoByte* signature, const std::size_t signature_length) noexcept
    {
        using namespace openssl_provider::detail;
        const bool is_pqc_v = ((alg & 0xFF'000000U) == kAlgSlhDsaBase) ||
                              ((alg & 0xFF'000000U) == kAlgMlDsaBase);
        if (alg != kAlgEcdsa && alg != kAlgRsaPss && !is_pqc_v) { return err_invalid_arg; }
        EVP_PKEY* pkey = ossl_asym_store_get(key);
        if (pkey == nullptr) { return err_invalid_arg; }
        if (is_pqc_v && ossl_asym_store_alg(key) != alg) { return err_invalid_arg; }

        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (ctx == nullptr) { return err_invalid_arg; }

        Status rv = err_invalid_arg;
        do {
            EVP_PKEY_CTX* pctx = nullptr;
            const char* digest = is_pqc_v ? nullptr : "SHA2-384";
            if (EVP_DigestVerifyInit_ex(ctx, &pctx, digest,
                                        nullptr, nullptr, pkey, nullptr) != ok) { break; }
            if (alg == kAlgRsaPss) {
                if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) != ok) { break; }
                if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) != ok) { break; }
            }
            const int r = EVP_DigestVerify(ctx, signature, signature_length,
                                           input, input_length);
            if (r == 1)  { rv = ok; break; }
            if (r == 0)  { rv = err_invalid_sig; break; }
            rv = err_invalid_arg;
        } while (false);

        EVP_MD_CTX_free(ctx);
        return rv;
    }

    [[nodiscard]]
    static Status raw_key_agreement(  // NOLINT(readability-function-size)
        const Algorithm alg,
        const KeyId private_key,
        const CryptoByte* peer_key, const std::size_t peer_key_length,
        CryptoByte* output, const std::size_t output_size,
        std::size_t* output_length) noexcept
    {
        using namespace openssl_provider::detail;
        if (alg != kAlgEcdh) { return err_invalid_arg; }

        EVP_PKEY* our_pkey = ossl_asym_store_get(private_key);
        if (our_pkey == nullptr) { return err_invalid_arg; }

        // Derive the curve name from our key so we can import the peer's public key.
        char curve_name[32]{}; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays,misc-const-correctness)
        const std::size_t name_len = sizeof(curve_name);
        if (EVP_PKEY_get_utf8_string_param(our_pkey,
                OSSL_PKEY_PARAM_GROUP_NAME,
                curve_name, name_len, nullptr) != ok) { return err_invalid_arg; }

        // Import peer uncompressed point (04||x||y) via EVP_PKEY_fromdata.
        OSSL_PARAM peer_params[] = {  // NOLINT(*)
            OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                curve_name, 0),
            OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                const_cast<CryptoByte*>(peer_key), peer_key_length),  // NOLINT(cppcoreguidelines-pro-type-const-cast)
            OSSL_PARAM_END
        };
        EVP_PKEY_CTX* peer_pctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
        if (peer_pctx == nullptr) { return err_invalid_arg; }
        EVP_PKEY* peer_pkey = nullptr;
        const Status rv_peer = (EVP_PKEY_fromdata_init(peer_pctx) == ok &&
            EVP_PKEY_fromdata(peer_pctx, &peer_pkey, EVP_PKEY_PUBLIC_KEY, peer_params) == ok)
            ? ok : err_invalid_arg;
        EVP_PKEY_CTX_free(peer_pctx);
        if (rv_peer != ok || peer_pkey == nullptr) { return err_invalid_arg; }

        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_pkey(nullptr, our_pkey, nullptr);
        Status rv = err_invalid_arg;
        if (ctx != nullptr) {
            if (EVP_PKEY_derive_init(ctx) == ok) {
                if (EVP_PKEY_derive_set_peer(ctx, peer_pkey) == ok) {
                    std::size_t len = output_size;
                    if (EVP_PKEY_derive(ctx, output, &len) == ok) {
                        *output_length = len;
                        rv = ok;
                    }
                }
            }
            EVP_PKEY_CTX_free(ctx);
        }
        EVP_PKEY_free(peer_pkey);
        return rv;
    }

    [[nodiscard]]
    static Status asymmetric_encrypt(  // NOLINT(readability-function-size)
        const KeyId key, const Algorithm alg,
        const CryptoByte* input, const std::size_t input_length,
        const CryptoByte* salt, const std::size_t salt_length,
        CryptoByte* output, const std::size_t output_size,
        std::size_t* output_length) noexcept
    {
        using namespace openssl_provider::detail;
        if (alg != kAlgRsaOaep) { return err_invalid_arg; }
        EVP_PKEY* pkey = ossl_asym_store_get(key);
        if (pkey == nullptr) { return err_invalid_arg; }

        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_pkey(nullptr, pkey, nullptr);
        if (ctx == nullptr) { return err_invalid_arg; }

        Status rv = err_invalid_arg;
        do {
            if (EVP_PKEY_encrypt_init(ctx) != ok) { break; }
            if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) != ok) { break; }
            if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha384()) != ok) { break; }
            if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha384()) != ok) { break; }
            if (salt_length > 0) {
                // OAEP label: must be heap-allocated; OpenSSL takes ownership.
                // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
                auto* label_copy = static_cast<unsigned char*>(OPENSSL_malloc(salt_length));
                if (label_copy == nullptr) { break; }
                std::memcpy(label_copy, salt, salt_length);
                if (EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, label_copy, static_cast<int>(salt_length)) != ok) {
                    OPENSSL_free(label_copy);
                    break;
                }
            }
            std::size_t len = output_size;
            if (EVP_PKEY_encrypt(ctx, output, &len, input, input_length) != ok) { break; }
            *output_length = len;
            rv = ok;
        } while (false);

        EVP_PKEY_CTX_free(ctx);
        return rv;
    }

    [[nodiscard]]
    static Status asymmetric_decrypt(  // NOLINT(readability-function-size)
        const KeyId key, const Algorithm alg,
        const CryptoByte* input, const std::size_t input_length,
        const CryptoByte* salt, const std::size_t salt_length,
        CryptoByte* output, const std::size_t output_size,
        std::size_t* output_length) noexcept
    {
        using namespace openssl_provider::detail;
        if (alg != kAlgRsaOaep) { return err_invalid_arg; }
        EVP_PKEY* pkey = ossl_asym_store_get(key);
        if (pkey == nullptr) { return err_invalid_arg; }

        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_pkey(nullptr, pkey, nullptr);
        if (ctx == nullptr) { return err_invalid_arg; }

        Status rv = err_invalid_arg;
        do {
            if (EVP_PKEY_decrypt_init(ctx) != ok) { break; }
            if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) != ok) { break; }
            if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha384()) != ok) { break; }
            if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha384()) != ok) { break; }
            if (salt_length > 0) {
                // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
                auto* label_copy = static_cast<unsigned char*>(OPENSSL_malloc(salt_length));
                if (label_copy == nullptr) { break; }
                std::memcpy(label_copy, salt, salt_length);
                if (EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, label_copy, static_cast<int>(salt_length)) != ok) {
                    OPENSSL_free(label_copy);
                    break;
                }
            }
            std::size_t len = output_size;
            if (EVP_PKEY_decrypt(ctx, output, &len, input, input_length) != ok) { break; }
            *output_length = len;
            rv = ok;
        } while (false);

        EVP_PKEY_CTX_free(ctx);
        return rv;
    }

    [[nodiscard]]
    static Status kem_encapsulate(
        const KeyId key, const Algorithm alg,
        CryptoByte* ciphertext, const std::size_t ciphertext_size, std::size_t* ciphertext_length,
        CryptoByte* shared_secret, const std::size_t shared_secret_size,
        std::size_t* shared_secret_length) noexcept
    {
        using namespace openssl_provider::detail;
        if ((alg & 0xFF'000000U) != kAlgMlKemBase) { return err_invalid_arg; }
        EVP_PKEY* pkey = ossl_asym_store_get(key);
        if (pkey == nullptr) { return err_invalid_arg; }
        if (ossl_asym_store_alg(key) != alg) { return err_invalid_arg; }

        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_pkey(nullptr, pkey, nullptr);
        if (ctx == nullptr) { return err_invalid_arg; }

        Status rv = err_invalid_arg;
        do {
            if (EVP_PKEY_encapsulate_init(ctx, nullptr) != ok) { break; }
            // Query output sizes first (pass nullptr buffers).
            std::size_t ct_len = 0;
            std::size_t ss_len = 0;
            if (EVP_PKEY_encapsulate(ctx, nullptr, &ct_len, nullptr, &ss_len) != ok) { break; }
            if (ct_len > ciphertext_size || ss_len > shared_secret_size) {
                rv = err_invalid_arg;
                break;
            }
            // Re-init is required before the actual call on some OpenSSL versions.
            if (EVP_PKEY_encapsulate_init(ctx, nullptr) != ok) { break; }
            if (EVP_PKEY_encapsulate(ctx,
                                     ciphertext, &ct_len,
                                     shared_secret, &ss_len) != ok) { break; }
            *ciphertext_length    = ct_len;
            *shared_secret_length = ss_len;
            rv = ok;
        } while (false);

        EVP_PKEY_CTX_free(ctx);
        return rv;
    }

    [[nodiscard]]
    static Status kem_decapsulate(
        const KeyId key, const Algorithm alg,
        const CryptoByte* ciphertext, const std::size_t ciphertext_length,
        CryptoByte* shared_secret, const std::size_t shared_secret_size,
        std::size_t* shared_secret_length) noexcept
    {
        using namespace openssl_provider::detail;
        if ((alg & 0xFF'000000U) != kAlgMlKemBase) { return err_invalid_arg; }
        EVP_PKEY* pkey = ossl_asym_store_get(key);
        if (pkey == nullptr) { return err_invalid_arg; }
        if (ossl_asym_store_alg(key) != alg) { return err_invalid_arg; }

        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_pkey(nullptr, pkey, nullptr);
        if (ctx == nullptr) { return err_invalid_arg; }

        Status rv = err_invalid_arg;
        do {
            if (EVP_PKEY_decapsulate_init(ctx, nullptr) != ok) { break; }
            std::size_t ss_len = shared_secret_size;
            if (EVP_PKEY_decapsulate(ctx,
                                     shared_secret, &ss_len,
                                     ciphertext, ciphertext_length) != ok) { break; }
            *shared_secret_length = ss_len;
            rv = ok;
        } while (false);

        EVP_PKEY_CTX_free(ctx);
        return rv;
    }

    [[nodiscard]]
    static Status key_derivation_setup(
        KdfOperation* operation, const Algorithm alg) noexcept
    {
        if (operation == nullptr) { return err_invalid_arg; }
        if (alg != kAlgHkdf && alg != kAlgHkdfExpand) { return err_invalid_arg; }

        EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
        if (kdf == nullptr) { return err_invalid_arg; }
        operation->ctx = EVP_KDF_CTX_new(kdf);
        EVP_KDF_free(kdf);
        if (operation->ctx == nullptr) { return err_invalid_arg; }

        // Store mode: full HKDF (extract+expand) vs expand-only.
        operation->mode = (alg == kAlgHkdfExpand)
                            ? EVP_KDF_HKDF_MODE_EXPAND_ONLY
                            : EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND;
        return ok;
    }

    [[nodiscard]]
    static Status key_derivation_input_key(
        KdfOperation* operation,
        const KdfStep step,
        const KeyId key) noexcept
    {
        using namespace openssl_provider::detail;
        if (operation == nullptr || step != kKdfStepSecret) { return err_invalid_arg; }
        const OpenSslRawSlot* slot = ossl_raw_store_get(key);
        if (slot == nullptr) { return err_invalid_arg; }
        // Store pointer + length; the raw slot outlives this operation.
        operation->secret     = slot->data.data();
        operation->secret_len = slot->len;
        operation->secret_key_id = key;
        return ok;
    }

    [[nodiscard]]
    static Status key_derivation_input_bytes(
        KdfOperation* operation,
        const KdfStep step,
        const CryptoByte* data, const std::size_t data_length) noexcept
    {
        if (operation == nullptr) { return err_invalid_arg; }
        if (step == kKdfStepSalt) {
            operation->salt     = data;
            operation->salt_len = data_length;
            return ok;
        }
        if (step == kKdfStepInfo) {
            operation->info     = data;
            operation->info_len = data_length;
            return ok;
        }
        return err_invalid_arg;
    }

    [[nodiscard]]
    static Status key_derivation_output_bytes(
        KdfOperation* operation,
        CryptoByte* output, const std::size_t output_length) noexcept
    {
        if (operation == nullptr || operation->ctx == nullptr) { return err_invalid_arg; }
        if (operation->secret == nullptr) { return err_invalid_arg; }

        // Build the parameter list.  Maximum 6 params + END.
        OSSL_PARAM params[7];  // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
        int n = 0;

        // Digest: always SHA2-384 (matching the rest of this library).
        params[n++] = OSSL_PARAM_construct_utf8_string(  // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
            OSSL_KDF_PARAM_DIGEST,
            const_cast<char*>("SHA2-384"),  // NOLINT(cppcoreguidelines-pro-type-const-cast)
            0);

        // Mode: extract+expand or expand-only.
        params[n++] = OSSL_PARAM_construct_int(  // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
            OSSL_KDF_PARAM_MODE, &operation->mode);

        // Key (secret / PRK).
        params[n++] = OSSL_PARAM_construct_octet_string(  // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
            OSSL_KDF_PARAM_KEY,
            const_cast<CryptoByte*>(operation->secret),  // NOLINT(cppcoreguidelines-pro-type-const-cast)
            operation->secret_len);

        // Salt (optional; omit for expand-only mode).
        if (operation->salt != nullptr && operation->salt_len > 0) {
            params[n++] = OSSL_PARAM_construct_octet_string(  // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
                OSSL_KDF_PARAM_SALT,
                const_cast<CryptoByte*>(operation->salt),  // NOLINT(cppcoreguidelines-pro-type-const-cast)
                operation->salt_len);
        }

        // Info (context, may be zero-length).
        params[n++] = OSSL_PARAM_construct_octet_string(  // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
            OSSL_KDF_PARAM_INFO,
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
            const_cast<CryptoByte*>(operation->info != nullptr ? operation->info
                                                                : reinterpret_cast<const CryptoByte*>("")),
            operation->info_len);

        params[n] = OSSL_PARAM_END;  // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)

        return EVP_KDF_derive(operation->ctx, output, output_length, params);
    }

    [[nodiscard]]
    static Status key_derivation_abort(KdfOperation* operation) noexcept {
        if (operation != nullptr && operation->ctx != nullptr) {
            EVP_KDF_CTX_free(operation->ctx);
            operation->ctx = nullptr;
        }
        return ok;
    }
};
