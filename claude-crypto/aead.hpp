/*
Copyright Permanence AI, 2026. All rights reserved.

*/

#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>

#include <psa/crypto.h>
#include <psa/crypto_sizes.h>
#include <psa/crypto_values.h>

#include "crypto_error.hpp"
#include "random.hpp"
#include "secure_buffer.hpp"


constexpr std::size_t AES256_KEY_SIZE_BYTES = 32;
constexpr std::size_t AES_GCM_IV_SIZE_BYTES = 12;


struct AesGcmResult {
    FixedSecureBuffer<AES_GCM_IV_SIZE_BYTES> iv;
    SecureBuffer                             ciphertext;
};


template<SecureBufferLike Plaintext>
[[nodiscard]]
auto aes256_gcm_encrypt(  // NOLINT(readability-function-cognitive-complexity)
    const FixedSecureBuffer<AES256_KEY_SIZE_BYTES>& key,
    const Plaintext& plaintext,
    const std::optional<SecureBuffer>& aad = std::nullopt)
    -> std::expected<AesGcmResult, CryptoError>
{
    constexpr std::size_t AES256_KEY_BITS = 256;

    if (psa_crypto_init() != PSA_SUCCESS) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InitFailed,
            "PSA crypto init failed"));
    }

    auto iv = random_bytes<AES_GCM_IV_SIZE_BYTES>();
    if (!iv.has_value()) {
        return std::unexpected(iv.error());
    }

    psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, AES256_KEY_BITS);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_GCM);

    mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
    if (psa_import_key(&attrs, key.data(), key.size(), &key_id) != PSA_SUCCESS) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyImportFailed,
            "Key import failed"));
    }

    const std::size_t output_size =
        PSA_AEAD_ENCRYPT_OUTPUT_SIZE(PSA_KEY_TYPE_AES, PSA_ALG_GCM, plaintext.size());
    SecureBuffer ciphertext(output_size);

    const CRYPTO_BYTE* aad_ptr  = aad.has_value() ? aad->data() : nullptr;
    const std::size_t   aad_size = aad.has_value() ? aad->size() : 0;

    std::size_t ciphertext_length = 0;
    const psa_status_t status = psa_aead_encrypt(
        key_id, PSA_ALG_GCM,
        iv->data(), iv->size(),
        aad_ptr, aad_size,
        plaintext.data(), plaintext.size(),
        ciphertext.data(), ciphertext.size(),
        &ciphertext_length);

    psa_destroy_key(key_id);

    if (status != PSA_SUCCESS) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::EncryptionFailed,
            "AES-256-GCM encryption failed"));
    }

    return AesGcmResult{
        .iv         = std::move(*iv),
        .ciphertext = std::move(ciphertext),
    };
}


[[nodiscard]]
inline auto aes256_gcm_decrypt(  // NOLINT(readability-function-cognitive-complexity)
    const FixedSecureBuffer<AES256_KEY_SIZE_BYTES>& key,
    const AesGcmResult& ciphertext,
    const std::optional<SecureBuffer>& aad = std::nullopt)
    -> std::expected<SecureBuffer, CryptoError>
{
    constexpr std::size_t AES256_KEY_BITS = 256;

    if (psa_crypto_init() != PSA_SUCCESS) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InitFailed,
            "PSA crypto init failed"));
    }

    psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, AES256_KEY_BITS);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_GCM);

    mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
    if (psa_import_key(&attrs, key.data(), key.size(), &key_id) != PSA_SUCCESS) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyImportFailed,
            "Key import failed"));
    }

    const CRYPTO_BYTE* aad_ptr  = aad.has_value() ? aad->data() : nullptr;
    const std::size_t   aad_size = aad.has_value() ? aad->size() : 0;

    const std::size_t plaintext_size =
        PSA_AEAD_DECRYPT_OUTPUT_SIZE(PSA_KEY_TYPE_AES, PSA_ALG_GCM, ciphertext.ciphertext.size());
    SecureBuffer plaintext(plaintext_size);

    std::size_t plaintext_length = 0;
    const psa_status_t status = psa_aead_decrypt(
        key_id, PSA_ALG_GCM,
        ciphertext.iv.data(), ciphertext.iv.size(),
        aad_ptr, aad_size,
        ciphertext.ciphertext.data(), ciphertext.ciphertext.size(),
        plaintext.data(), plaintext.size(),
        &plaintext_length);

    psa_destroy_key(key_id);

    if (status != PSA_SUCCESS) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::DecryptionFailed,
            "AES-256-GCM decryption failed"));
    }

    return plaintext;
}
