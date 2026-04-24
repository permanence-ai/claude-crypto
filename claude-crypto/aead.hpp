/*
Copyright Permanence AI, 2026. All rights reserved.

*/

#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <stdexcept>

#include <psa/crypto.h>
#include <psa/crypto_sizes.h>
#include <psa/crypto_values.h>

#include "crypto_error.hpp"
#include "secure_buffer.hpp"


struct AesGcmResult {
    SecureBuffer iv;
    SecureBuffer ciphertext;
};


[[nodiscard]]
inline auto aes256_gcm_encrypt(const SecureBuffer& key,
                               const SecureBuffer& plaintext,
                               const std::optional<SecureBuffer>& aad = std::nullopt) -> AesGcmResult
{
    constexpr std::size_t AES256_KEY_BITS = 256;
    constexpr std::size_t IV_SIZE_BYTES   = 12;

    if (psa_crypto_init() != PSA_SUCCESS) {
        throw std::runtime_error("PSA crypto init failed");
    }

    SecureBuffer iv(IV_SIZE_BYTES);
    if (psa_generate_random(iv.data(), iv.size()) != PSA_SUCCESS) {
        throw std::runtime_error("IV generation failed");
    }

    psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, AES256_KEY_BITS);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_GCM);

    mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
    if (psa_import_key(&attrs, key.data(), key.size(), &key_id) != PSA_SUCCESS) {
        throw std::runtime_error("Key import failed");
    }

    const std::size_t output_size =
        PSA_AEAD_ENCRYPT_OUTPUT_SIZE(PSA_KEY_TYPE_AES, PSA_ALG_GCM, plaintext.size());
    SecureBuffer ciphertext(output_size);

    const std::uint8_t* aad_ptr  = aad.has_value() ? aad->data() : nullptr;
    const std::size_t   aad_size = aad.has_value() ? aad->size() : 0;

    std::size_t ciphertext_length = 0;
    const psa_status_t status = psa_aead_encrypt(
        key_id, PSA_ALG_GCM,
        iv.data(), iv.size(),
        aad_ptr, aad_size,
        plaintext.data(), plaintext.size(),
        ciphertext.data(), ciphertext.size(),
        &ciphertext_length);

    psa_destroy_key(key_id);

    if (status != PSA_SUCCESS) {
        throw std::runtime_error("AES-256-GCM encryption failed");
    }

    return AesGcmResult{std::move(iv), std::move(ciphertext)};
}


[[nodiscard]]
inline auto aes256_gcm_decrypt(const SecureBuffer& key,
                               const AesGcmResult& ciphertext,
                               const std::optional<SecureBuffer>& aad = std::nullopt)
    -> std::expected<SecureBuffer, CryptoError>
{
    constexpr std::size_t AES256_KEY_BITS = 256;

    if (psa_crypto_init() != PSA_SUCCESS) {
        return std::unexpected(CryptoError("PSA crypto init failed"));
    }

    psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, AES256_KEY_BITS);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_GCM);

    mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
    if (psa_import_key(&attrs, key.data(), key.size(), &key_id) != PSA_SUCCESS) {
        return std::unexpected(CryptoError("Key import failed"));
    }

    const std::uint8_t* aad_ptr  = aad.has_value() ? aad->data() : nullptr;
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
        return std::unexpected(CryptoError("AES-256-GCM decryption failed"));
    }

    return plaintext;
}
