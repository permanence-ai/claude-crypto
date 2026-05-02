/*
Copyright Permanence AI, 2026. All rights reserved.

*/

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

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

#include "defs.hpp"
#include "openssl_key_store.hpp"
#include "sha_variant.hpp"


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
        return plaintext_size + 16U;  // + 128-bit GCM tag
    }
    [[nodiscard]]
    static std::size_t aes_gcm_decrypt_output_size(const std::size_t ciphertext_size) noexcept {
        return ciphertext_size > 16U ? ciphertext_size - 16U : 0U;
    }
    [[nodiscard]]
    static std::size_t chacha20_encrypt_output_size(const std::size_t plaintext_size) noexcept {
        return plaintext_size + 16U;  // + 128-bit Poly1305 tag
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
        (void)attributes; (void)data; (void)data_length; (void)key;
        return err_invalid_arg;  // TODO
    }

    [[nodiscard]]
    static Status generate_key(
        const KeyAttributes* attributes,
        KeyId* key) noexcept
    {
        (void)attributes; (void)key;
        return err_invalid_arg;  // TODO
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
        (void)key; (void)data; (void)data_size; (void)data_length;
        return err_invalid_arg;  // TODO
    }

    [[nodiscard]]
    static Status export_public_key(
        const KeyId key,
        CryptoByte* data, const std::size_t data_size, std::size_t* data_length) noexcept
    {
        (void)key; (void)data; (void)data_size; (void)data_length;
        return err_invalid_arg;  // TODO
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
        (void)key; (void)alg; (void)input; (void)input_length;
        (void)mac; (void)mac_size; (void)mac_length;
        return err_invalid_arg;  // TODO
    }

    [[nodiscard]]
    static Status mac_verify(
        const KeyId key, const Algorithm alg,
        const CryptoByte* input, const std::size_t input_length,
        const CryptoByte* mac, const std::size_t mac_length) noexcept
    {
        (void)key; (void)alg; (void)input; (void)input_length;
        (void)mac; (void)mac_length;
        return err_invalid_arg;  // TODO
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
        (void)key; (void)alg; (void)nonce; (void)nonce_length;
        (void)additional_data; (void)additional_data_length;
        (void)plaintext; (void)plaintext_length;
        (void)ciphertext; (void)ciphertext_size; (void)ciphertext_length;
        return err_invalid_arg;  // TODO
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
        (void)key; (void)alg; (void)nonce; (void)nonce_length;
        (void)additional_data; (void)additional_data_length;
        (void)ciphertext; (void)ciphertext_length;
        (void)plaintext; (void)plaintext_size; (void)plaintext_length;
        return err_invalid_arg;  // TODO
    }

    [[nodiscard]]
    static Status sign_message(  // NOLINT(readability-function-size)
        const KeyId key, const Algorithm alg,
        const CryptoByte* input, const std::size_t input_length,
        CryptoByte* signature, const std::size_t signature_size,
        std::size_t* signature_length) noexcept
    {
        (void)key; (void)alg; (void)input; (void)input_length;
        (void)signature; (void)signature_size; (void)signature_length;
        return err_invalid_arg;  // TODO
    }

    [[nodiscard]]
    static Status verify_message(
        const KeyId key, const Algorithm alg,
        const CryptoByte* input, const std::size_t input_length,
        const CryptoByte* signature, const std::size_t signature_length) noexcept
    {
        (void)key; (void)alg; (void)input; (void)input_length;
        (void)signature; (void)signature_length;
        return err_invalid_arg;  // TODO
    }

    [[nodiscard]]
    static Status raw_key_agreement(  // NOLINT(readability-function-size)
        const Algorithm alg,
        const KeyId private_key,
        const CryptoByte* peer_key, const std::size_t peer_key_length,
        CryptoByte* output, const std::size_t output_size,
        std::size_t* output_length) noexcept
    {
        (void)alg; (void)private_key; (void)peer_key; (void)peer_key_length;
        (void)output; (void)output_size; (void)output_length;
        return err_invalid_arg;  // TODO
    }

    [[nodiscard]]
    static Status asymmetric_encrypt(  // NOLINT(readability-function-size)
        const KeyId key, const Algorithm alg,
        const CryptoByte* input, const std::size_t input_length,
        const CryptoByte* salt, const std::size_t salt_length,
        CryptoByte* output, const std::size_t output_size,
        std::size_t* output_length) noexcept
    {
        (void)key; (void)alg; (void)input; (void)input_length;
        (void)salt; (void)salt_length;
        (void)output; (void)output_size; (void)output_length;
        return err_invalid_arg;  // TODO
    }

    [[nodiscard]]
    static Status asymmetric_decrypt(  // NOLINT(readability-function-size)
        const KeyId key, const Algorithm alg,
        const CryptoByte* input, const std::size_t input_length,
        const CryptoByte* salt, const std::size_t salt_length,
        CryptoByte* output, const std::size_t output_size,
        std::size_t* output_length) noexcept
    {
        (void)key; (void)alg; (void)input; (void)input_length;
        (void)salt; (void)salt_length;
        (void)output; (void)output_size; (void)output_length;
        return err_invalid_arg;  // TODO
    }

    [[nodiscard]]
    static Status key_derivation_setup(
        KdfOperation* operation, const Algorithm alg) noexcept
    {
        (void)operation; (void)alg;
        return err_invalid_arg;  // TODO
    }

    [[nodiscard]]
    static Status key_derivation_input_key(
        KdfOperation* operation,
        const KdfStep step,
        const KeyId key) noexcept
    {
        (void)operation; (void)step; (void)key;
        return err_invalid_arg;  // TODO
    }

    [[nodiscard]]
    static Status key_derivation_input_bytes(
        KdfOperation* operation,
        const KdfStep step,
        const CryptoByte* data, const std::size_t data_length) noexcept
    {
        (void)operation; (void)step; (void)data; (void)data_length;
        return err_invalid_arg;  // TODO
    }

    [[nodiscard]]
    static Status key_derivation_output_bytes(
        KdfOperation* operation,
        CryptoByte* output, const std::size_t output_length) noexcept
    {
        (void)operation; (void)output; (void)output_length;
        return err_invalid_arg;  // TODO
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
