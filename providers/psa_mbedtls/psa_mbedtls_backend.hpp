/*
Copyright Permanence AI, 2026. All rights reserved.

*/

#pragma once

#include <cstddef>

#include <psa/crypto.h>
#include <psa/crypto_sizes.h>
#include <psa/crypto_values.h>

#include "defs.hpp"
#include "sha_variant.hpp"


// Production PSA/MbedTLS backend — every method is a direct forwarding call to
// the corresponding PSA C function or macro.  Tests substitute MockPsaBackend
// to exercise error branches without needing to induce real PSA failures.
struct RealPsaBackend {
    // Associated types — insulate callers from PSA/MbedTLS concrete type names.
    using Status        = psa_status_t;
    using KeyId         = mbedtls_svc_key_id_t;
    using Algorithm     = psa_algorithm_t;
    using KeyAttributes = psa_key_attributes_t;
    using KdfOperation  = psa_key_derivation_operation_t;
    using KdfStep       = psa_key_derivation_step_t;

    // Status sentinels — avoids PSA_SUCCESS / PSA_ERROR_* leaking into generic code.
    static constexpr Status ok              = PSA_SUCCESS;
    static constexpr Status err_invalid_sig = PSA_ERROR_INVALID_SIGNATURE;
    static constexpr Status err_invalid_arg = PSA_ERROR_INVALID_ARGUMENT;

    // Object factories for provider-specific init macros.
    static KeyId null_key_id() noexcept {
        const KeyId k = MBEDTLS_SVC_KEY_ID_INIT;
        return k;
    }
    static KeyAttributes make_key_attrs() noexcept {
        KeyAttributes a = PSA_KEY_ATTRIBUTES_INIT;
        return a;
    }
    static KdfOperation make_kdf_op() noexcept {
        KdfOperation o = PSA_KEY_DERIVATION_OPERATION_INIT;
        return o;
    }

    static Status crypto_init() {
        return psa_crypto_init();
    }

    static Status generate_random(CryptoByte* output, const std::size_t output_size) {
        return psa_generate_random(output, output_size);
    }

    static Status hash_compute(
        const Algorithm alg,
        const CryptoByte* input, const std::size_t input_length,
        CryptoByte* hash, const std::size_t hash_size, std::size_t* hash_length)
    {
        return psa_hash_compute(alg, input, input_length, hash, hash_size, hash_length);
    }

    static Status import_key(
        const KeyAttributes* attributes,
        const CryptoByte* data, const std::size_t data_length,
        KeyId* key)
    {
        return psa_import_key(attributes, data, data_length, key);
    }

    static Status generate_key(
        const KeyAttributes* attributes,
        KeyId* key)
    {
        return psa_generate_key(attributes, key);
    }

    static Status destroy_key(const KeyId key) {
        return psa_destroy_key(key);
    }

    static Status export_key(
        const KeyId key,
        CryptoByte* data, const std::size_t data_size, std::size_t* data_length)
    {
        return psa_export_key(key, data, data_size, data_length);
    }

    static Status export_public_key(
        const KeyId key,
        CryptoByte* data, const std::size_t data_size, std::size_t* data_length)
    {
        return psa_export_public_key(key, data, data_size, data_length);
    }

    static Status mac_compute(  // NOLINT(readability-function-size)
        const KeyId key, const Algorithm alg,
        const CryptoByte* input, const std::size_t input_length,
        CryptoByte* mac, const std::size_t mac_size, std::size_t* mac_length)
    {
        return psa_mac_compute(key, alg, input, input_length, mac, mac_size, mac_length);
    }

    static Status mac_verify(
        const KeyId key, const Algorithm alg,
        const CryptoByte* input, const std::size_t input_length,
        const CryptoByte* mac, const std::size_t mac_length)
    {
        return psa_mac_verify(key, alg, input, input_length, mac, mac_length);
    }

    static Status aead_encrypt(  // NOLINT(readability-function-size)
        const KeyId key, const Algorithm alg,
        const CryptoByte* nonce, const std::size_t nonce_length,
        const CryptoByte* additional_data, const std::size_t additional_data_length,
        const CryptoByte* plaintext, const std::size_t plaintext_length,
        CryptoByte* ciphertext, const std::size_t ciphertext_size,
        std::size_t* ciphertext_length)
    {
        return psa_aead_encrypt(
            key, alg,
            nonce, nonce_length,
            additional_data, additional_data_length,
            plaintext, plaintext_length,
            ciphertext, ciphertext_size, ciphertext_length);
    }

    static Status aead_decrypt(  // NOLINT(readability-function-size)
        const KeyId key, const Algorithm alg,
        const CryptoByte* nonce, const std::size_t nonce_length,
        const CryptoByte* additional_data, const std::size_t additional_data_length,
        const CryptoByte* ciphertext, const std::size_t ciphertext_length,
        CryptoByte* plaintext, const std::size_t plaintext_size,
        std::size_t* plaintext_length)
    {
        return psa_aead_decrypt(
            key, alg,
            nonce, nonce_length,
            additional_data, additional_data_length,
            ciphertext, ciphertext_length,
            plaintext, plaintext_size, plaintext_length);
    }

    static Status sign_message(  // NOLINT(readability-function-size)
        const KeyId key, const Algorithm alg,
        const CryptoByte* input, const std::size_t input_length,
        CryptoByte* signature, const std::size_t signature_size,
        std::size_t* signature_length)
    {
        return psa_sign_message(
            key, alg, input, input_length,
            signature, signature_size, signature_length);
    }

    static Status verify_message(
        const KeyId key, const Algorithm alg,
        const CryptoByte* input, const std::size_t input_length,
        const CryptoByte* signature, const std::size_t signature_length)
    {
        return psa_verify_message(
            key, alg, input, input_length, signature, signature_length);
    }

    static Status raw_key_agreement(  // NOLINT(readability-function-size)
        const Algorithm alg,
        const KeyId private_key,
        const CryptoByte* peer_key, const std::size_t peer_key_length,
        CryptoByte* output, const std::size_t output_size,
        std::size_t* output_length)
    {
        return psa_raw_key_agreement(
            alg, private_key, peer_key, peer_key_length,
            output, output_size, output_length);
    }

    static Status asymmetric_encrypt(  // NOLINT(readability-function-size)
        const KeyId key, const Algorithm alg,
        const CryptoByte* input, const std::size_t input_length,
        const CryptoByte* salt, const std::size_t salt_length,
        CryptoByte* output, const std::size_t output_size,
        std::size_t* output_length)
    {
        return psa_asymmetric_encrypt(
            key, alg, input, input_length, salt, salt_length,
            output, output_size, output_length);
    }

    static Status asymmetric_decrypt(  // NOLINT(readability-function-size)
        const KeyId key, const Algorithm alg,
        const CryptoByte* input, const std::size_t input_length,
        const CryptoByte* salt, const std::size_t salt_length,
        CryptoByte* output, const std::size_t output_size,
        std::size_t* output_length)
    {
        return psa_asymmetric_decrypt(
            key, alg, input, input_length, salt, salt_length,
            output, output_size, output_length);
    }

    static Status key_derivation_setup(
        KdfOperation* operation, const Algorithm alg)
    {
        return psa_key_derivation_setup(operation, alg);
    }

    static Status key_derivation_input_key(
        KdfOperation* operation,
        const KdfStep step,
        const KeyId key)
    {
        return psa_key_derivation_input_key(operation, step, key);
    }

    static Status key_derivation_input_bytes(
        KdfOperation* operation,
        const KdfStep step,
        const CryptoByte* data, const std::size_t data_length)
    {
        return psa_key_derivation_input_bytes(operation, step, data, data_length);
    }

    static Status key_derivation_output_bytes(
        KdfOperation* operation,
        CryptoByte* output, const std::size_t output_length)
    {
        return psa_key_derivation_output_bytes(operation, output, output_length);
    }

    static Status key_derivation_abort(KdfOperation* operation) {
        return psa_key_derivation_abort(operation);
    }

    // -------------------------------------------------------------------------
    // Algorithm constants — provider-native algorithm selectors.
    // -------------------------------------------------------------------------
    static Algorithm alg_sha(const ShaVariant v) noexcept {
        switch (v) {
            case ShaVariant::Sha256:   return PSA_ALG_SHA_256;
            case ShaVariant::Sha384:   return PSA_ALG_SHA_384;
            case ShaVariant::Sha512:   return PSA_ALG_SHA_512;
            case ShaVariant::Sha3_256: return PSA_ALG_SHA3_256;
            case ShaVariant::Sha3_384: return PSA_ALG_SHA3_384;
            case ShaVariant::Sha3_512: return PSA_ALG_SHA3_512;
        }
    }
    static Algorithm alg_hmac(const ShaVariant v) noexcept {
        return PSA_ALG_HMAC(alg_sha(v));
    }
    static constexpr Algorithm alg_ecdsa()              noexcept { return PSA_ALG_ECDSA(PSA_ALG_SHA_384); }
    static constexpr Algorithm alg_ecdh()               noexcept { return PSA_ALG_ECDH; }
    static constexpr Algorithm alg_hkdf()               noexcept { return PSA_ALG_HKDF(PSA_ALG_SHA_384); }
    static constexpr Algorithm alg_hkdf_expand()        noexcept { return PSA_ALG_HKDF_EXPAND(PSA_ALG_SHA_384); }
    static constexpr Algorithm alg_aes_gcm()            noexcept { return PSA_ALG_GCM; }
    static constexpr Algorithm alg_chacha20_poly1305()  noexcept { return PSA_ALG_CHACHA20_POLY1305; }
    static constexpr Algorithm alg_rsa_oaep()           noexcept { return PSA_ALG_RSA_OAEP(PSA_ALG_SHA_384); }
    static constexpr Algorithm alg_rsa_pss()            noexcept { return PSA_ALG_RSA_PSS(PSA_ALG_SHA_384); }

    // -------------------------------------------------------------------------
    // KDF step constants.
    // -------------------------------------------------------------------------
    static constexpr KdfStep kdf_step_secret() noexcept { return PSA_KEY_DERIVATION_INPUT_SECRET; }
    static constexpr KdfStep kdf_step_salt()   noexcept { return PSA_KEY_DERIVATION_INPUT_SALT;   }
    static constexpr KdfStep kdf_step_info()   noexcept { return PSA_KEY_DERIVATION_INPUT_INFO;   }

    // -------------------------------------------------------------------------
    // Key attribute factories.
    // -------------------------------------------------------------------------
    static KeyAttributes make_hkdf_derive_attrs(const std::size_t key_size_bits) noexcept {
        KeyAttributes a = PSA_KEY_ATTRIBUTES_INIT;
        psa_set_key_type(&a, PSA_KEY_TYPE_DERIVE);
        psa_set_key_bits(&a, static_cast<psa_key_bits_t>(key_size_bits));
        psa_set_key_usage_flags(&a, PSA_KEY_USAGE_DERIVE);
        psa_set_key_algorithm(&a, alg_hkdf());
        return a;
    }
    static KeyAttributes make_hkdf_expand_derive_attrs(const std::size_t key_size_bits) noexcept {
        KeyAttributes a = PSA_KEY_ATTRIBUTES_INIT;
        psa_set_key_type(&a, PSA_KEY_TYPE_DERIVE);
        psa_set_key_bits(&a, static_cast<psa_key_bits_t>(key_size_bits));
        psa_set_key_usage_flags(&a, PSA_KEY_USAGE_DERIVE);
        psa_set_key_algorithm(&a, alg_hkdf_expand());
        return a;
    }
    static KeyAttributes make_hmac_generate_attrs(const ShaVariant v,
                                                  const std::size_t key_size_bits) noexcept {
        KeyAttributes a = PSA_KEY_ATTRIBUTES_INIT;
        psa_set_key_type(&a, PSA_KEY_TYPE_HMAC);
        psa_set_key_bits(&a, static_cast<psa_key_bits_t>(key_size_bits));
        psa_set_key_usage_flags(&a, PSA_KEY_USAGE_SIGN_MESSAGE);
        psa_set_key_algorithm(&a, alg_hmac(v));
        return a;
    }
    static KeyAttributes make_hmac_verify_attrs(const ShaVariant v,
                                                const std::size_t key_size_bits) noexcept {
        KeyAttributes a = PSA_KEY_ATTRIBUTES_INIT;
        psa_set_key_type(&a, PSA_KEY_TYPE_HMAC);
        psa_set_key_bits(&a, static_cast<psa_key_bits_t>(key_size_bits));
        psa_set_key_usage_flags(&a, PSA_KEY_USAGE_VERIFY_MESSAGE);
        psa_set_key_algorithm(&a, alg_hmac(v));
        return a;
    }
    static KeyAttributes make_ecdsa_generate_attrs(const std::size_t key_bits) noexcept {
        KeyAttributes a = PSA_KEY_ATTRIBUTES_INIT;
        psa_set_key_type(&a, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
        psa_set_key_bits(&a, static_cast<psa_key_bits_t>(key_bits));
        psa_set_key_usage_flags(&a, PSA_KEY_USAGE_SIGN_MESSAGE |
                                    PSA_KEY_USAGE_VERIFY_MESSAGE |
                                    PSA_KEY_USAGE_EXPORT);
        psa_set_key_algorithm(&a, alg_ecdsa());
        return a;
    }
    static KeyAttributes make_ecdsa_sign_attrs(const std::size_t key_bits) noexcept {
        KeyAttributes a = PSA_KEY_ATTRIBUTES_INIT;
        psa_set_key_type(&a, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
        psa_set_key_bits(&a, static_cast<psa_key_bits_t>(key_bits));
        psa_set_key_usage_flags(&a, PSA_KEY_USAGE_SIGN_MESSAGE);
        psa_set_key_algorithm(&a, alg_ecdsa());
        return a;
    }
    static KeyAttributes make_ecdsa_verify_attrs(const std::size_t key_bits) noexcept {
        KeyAttributes a = PSA_KEY_ATTRIBUTES_INIT;
        psa_set_key_type(&a, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
        psa_set_key_bits(&a, static_cast<psa_key_bits_t>(key_bits));
        psa_set_key_usage_flags(&a, PSA_KEY_USAGE_VERIFY_MESSAGE);
        psa_set_key_algorithm(&a, alg_ecdsa());
        return a;
    }
    static KeyAttributes make_ecdh_generate_attrs(const std::size_t key_bits) noexcept {
        KeyAttributes a = PSA_KEY_ATTRIBUTES_INIT;
        psa_set_key_type(&a, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
        psa_set_key_bits(&a, static_cast<psa_key_bits_t>(key_bits));
        psa_set_key_usage_flags(&a, PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
        psa_set_key_algorithm(&a, alg_ecdh());
        return a;
    }
    static KeyAttributes make_ecdh_agree_attrs(const std::size_t key_bits) noexcept {
        KeyAttributes a = PSA_KEY_ATTRIBUTES_INIT;
        psa_set_key_type(&a, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
        psa_set_key_bits(&a, static_cast<psa_key_bits_t>(key_bits));
        psa_set_key_usage_flags(&a, PSA_KEY_USAGE_DERIVE);
        psa_set_key_algorithm(&a, alg_ecdh());
        return a;
    }
    static KeyAttributes make_aes256_gcm_encrypt_attrs() noexcept {
        KeyAttributes a = PSA_KEY_ATTRIBUTES_INIT;
        psa_set_key_type(&a, PSA_KEY_TYPE_AES);
        psa_set_key_bits(&a, static_cast<psa_key_bits_t>(aes256_key_bits));
        psa_set_key_usage_flags(&a, PSA_KEY_USAGE_ENCRYPT);
        psa_set_key_algorithm(&a, alg_aes_gcm());
        return a;
    }
    static KeyAttributes make_aes256_gcm_decrypt_attrs() noexcept {
        KeyAttributes a = PSA_KEY_ATTRIBUTES_INIT;
        psa_set_key_type(&a, PSA_KEY_TYPE_AES);
        psa_set_key_bits(&a, static_cast<psa_key_bits_t>(aes256_key_bits));
        psa_set_key_usage_flags(&a, PSA_KEY_USAGE_DECRYPT);
        psa_set_key_algorithm(&a, alg_aes_gcm());
        return a;
    }
    static KeyAttributes make_chacha20_poly1305_encrypt_attrs() noexcept {
        KeyAttributes a = PSA_KEY_ATTRIBUTES_INIT;
        psa_set_key_type(&a, PSA_KEY_TYPE_CHACHA20);
        psa_set_key_bits(&a, static_cast<psa_key_bits_t>(chacha20_key_bits));
        psa_set_key_usage_flags(&a, PSA_KEY_USAGE_ENCRYPT);
        psa_set_key_algorithm(&a, alg_chacha20_poly1305());
        return a;
    }
    static KeyAttributes make_chacha20_poly1305_decrypt_attrs() noexcept {
        KeyAttributes a = PSA_KEY_ATTRIBUTES_INIT;
        psa_set_key_type(&a, PSA_KEY_TYPE_CHACHA20);
        psa_set_key_bits(&a, static_cast<psa_key_bits_t>(chacha20_key_bits));
        psa_set_key_usage_flags(&a, PSA_KEY_USAGE_DECRYPT);
        psa_set_key_algorithm(&a, alg_chacha20_poly1305());
        return a;
    }
    static KeyAttributes make_rsa_oaep_encrypt_attrs(const std::size_t key_bits) noexcept {
        KeyAttributes a = PSA_KEY_ATTRIBUTES_INIT;
        psa_set_key_type(&a, PSA_KEY_TYPE_RSA_PUBLIC_KEY);
        psa_set_key_bits(&a, static_cast<psa_key_bits_t>(key_bits));
        psa_set_key_usage_flags(&a, PSA_KEY_USAGE_ENCRYPT);
        psa_set_key_algorithm(&a, alg_rsa_oaep());
        return a;
    }
    static KeyAttributes make_rsa_oaep_decrypt_attrs(const std::size_t key_bits) noexcept {
        KeyAttributes a = PSA_KEY_ATTRIBUTES_INIT;
        psa_set_key_type(&a, PSA_KEY_TYPE_RSA_KEY_PAIR);
        psa_set_key_bits(&a, static_cast<psa_key_bits_t>(key_bits));
        psa_set_key_usage_flags(&a, PSA_KEY_USAGE_DECRYPT);
        psa_set_key_algorithm(&a, alg_rsa_oaep());
        return a;
    }
    static KeyAttributes make_rsa_pss_sign_attrs(const std::size_t key_bits) noexcept {
        KeyAttributes a = PSA_KEY_ATTRIBUTES_INIT;
        psa_set_key_type(&a, PSA_KEY_TYPE_RSA_KEY_PAIR);
        psa_set_key_bits(&a, static_cast<psa_key_bits_t>(key_bits));
        psa_set_key_usage_flags(&a, PSA_KEY_USAGE_SIGN_MESSAGE);
        psa_set_key_algorithm(&a, alg_rsa_pss());
        return a;
    }
    static KeyAttributes make_rsa_pss_verify_attrs(const std::size_t key_bits) noexcept {
        KeyAttributes a = PSA_KEY_ATTRIBUTES_INIT;
        psa_set_key_type(&a, PSA_KEY_TYPE_RSA_PUBLIC_KEY);
        psa_set_key_bits(&a, static_cast<psa_key_bits_t>(key_bits));
        psa_set_key_usage_flags(&a, PSA_KEY_USAGE_VERIFY_MESSAGE);
        psa_set_key_algorithm(&a, alg_rsa_pss());
        return a;
    }
    static KeyAttributes make_rsa_key_pair_attrs(const std::size_t key_bits) noexcept {
        KeyAttributes a = PSA_KEY_ATTRIBUTES_INIT;
        psa_set_key_type(&a, PSA_KEY_TYPE_RSA_KEY_PAIR);
        psa_set_key_bits(&a, static_cast<psa_key_bits_t>(key_bits));
        psa_set_key_usage_flags(&a, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT |
                                    PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE |
                                    PSA_KEY_USAGE_EXPORT);
        psa_set_key_algorithm(&a, alg_rsa_oaep());
        return a;
    }

    // -------------------------------------------------------------------------
    // Output size helpers — abstract PSA_*_OUTPUT_SIZE macros.
    // -------------------------------------------------------------------------
    static std::size_t ecdsa_sign_output_size(const std::size_t key_bits) noexcept {
        return PSA_SIGN_OUTPUT_SIZE(
            PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1),
            static_cast<psa_key_bits_t>(key_bits),
            alg_ecdsa());
    }
    static std::size_t ecdh_shared_secret_size(const std::size_t key_bits) noexcept {
        return PSA_RAW_KEY_AGREEMENT_OUTPUT_SIZE(
            PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1),
            static_cast<psa_key_bits_t>(key_bits));
    }
    static std::size_t ec_private_key_export_size(const std::size_t key_bits) noexcept {
        return PSA_EXPORT_KEY_OUTPUT_SIZE(
            PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1),
            static_cast<psa_key_bits_t>(key_bits));
    }
    static std::size_t ec_public_key_export_size(const std::size_t key_bits) noexcept {
        return PSA_EXPORT_PUBLIC_KEY_OUTPUT_SIZE(
            PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1),
            static_cast<psa_key_bits_t>(key_bits));
    }
    static std::size_t aes_gcm_encrypt_output_size(const std::size_t plaintext_size) noexcept {
        return PSA_AEAD_ENCRYPT_OUTPUT_SIZE(PSA_KEY_TYPE_AES, PSA_ALG_GCM, plaintext_size);
    }
    static std::size_t aes_gcm_decrypt_output_size(const std::size_t ciphertext_size) noexcept {
        return PSA_AEAD_DECRYPT_OUTPUT_SIZE(PSA_KEY_TYPE_AES, PSA_ALG_GCM, ciphertext_size);
    }
    static std::size_t chacha20_encrypt_output_size(const std::size_t plaintext_size) noexcept {
        return PSA_AEAD_ENCRYPT_OUTPUT_SIZE(
            PSA_KEY_TYPE_CHACHA20, PSA_ALG_CHACHA20_POLY1305, plaintext_size);
    }
    static std::size_t chacha20_decrypt_output_size(const std::size_t ciphertext_size) noexcept {
        return PSA_AEAD_DECRYPT_OUTPUT_SIZE(
            PSA_KEY_TYPE_CHACHA20, PSA_ALG_CHACHA20_POLY1305, ciphertext_size);
    }
    static std::size_t rsa_oaep_encrypt_output_size(const std::size_t key_bits) noexcept {
        return PSA_ASYMMETRIC_ENCRYPT_OUTPUT_SIZE(
            PSA_KEY_TYPE_RSA_PUBLIC_KEY,
            static_cast<psa_key_bits_t>(key_bits),
            alg_rsa_oaep());
    }
    static std::size_t rsa_oaep_decrypt_output_size(const std::size_t key_bits) noexcept {
        return PSA_ASYMMETRIC_DECRYPT_OUTPUT_SIZE(
            PSA_KEY_TYPE_RSA_KEY_PAIR,
            static_cast<psa_key_bits_t>(key_bits),
            alg_rsa_oaep());
    }
    static std::size_t rsa_pss_sign_output_size(const std::size_t key_bits) noexcept {
        return PSA_SIGN_OUTPUT_SIZE(
            PSA_KEY_TYPE_RSA_KEY_PAIR,
            static_cast<psa_key_bits_t>(key_bits),
            alg_rsa_pss());
    }
    static std::size_t rsa_private_key_export_size(const std::size_t key_bits) noexcept {
        return PSA_EXPORT_KEY_OUTPUT_SIZE(
            PSA_KEY_TYPE_RSA_KEY_PAIR,
            static_cast<psa_key_bits_t>(key_bits));
    }
    static std::size_t rsa_public_key_export_size(const std::size_t key_bits) noexcept {
        return PSA_EXPORT_PUBLIC_KEY_OUTPUT_SIZE(
            PSA_KEY_TYPE_RSA_KEY_PAIR,
            static_cast<psa_key_bits_t>(key_bits));
    }
};
