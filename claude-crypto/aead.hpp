/*
Copyright Permanence AI, 2026. All rights reserved.

*/

#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>

#include <psa/crypto_sizes.h>
#include <psa/crypto_values.h>

#include "crypto_error.hpp"
#include "psa_backend.hpp"
#include "random.hpp"
#include "secure_buffer.hpp"


constexpr std::size_t aes256_key_size_bytes           = 32;
constexpr std::size_t aes_gcm_iv_size_bytes            = 12;
constexpr std::size_t chacha20_key_size_bytes           = 32;
constexpr std::size_t chacha20_poly1305_iv_size_bytes   = 12;


struct AesGcmResult {
    FixedSecureBuffer<aes_gcm_iv_size_bytes> iv;
    SecureBuffer                             ciphertext;
};


struct ChaCha20Poly1305Result {
    FixedSecureBuffer<chacha20_poly1305_iv_size_bytes> iv;
    SecureBuffer                                       ciphertext;
};


template<typename PSA = RealPsaBackend, SecureBufferLike Plaintext>
[[nodiscard]]
auto aes256_gcm_encrypt_impl(  // NOLINT(readability-function-cognitive-complexity)
    const FixedSecureBuffer<aes256_key_size_bytes>& key,
    const Plaintext& plaintext,
    const std::optional<SecureBuffer>& aad = std::nullopt)
    -> std::expected<AesGcmResult, CryptoError>
{
    constexpr std::size_t aes256_key_bits = 256;

    if (PSA::crypto_init() != PSA_SUCCESS) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InitFailed,
            "PSA crypto init failed"));
    }

    auto iv = random_bytes_fixed_impl<aes_gcm_iv_size_bytes, PSA>();
    if (!iv.has_value()) {
        return std::unexpected(iv.error());
    }

    psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, aes256_key_bits);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_GCM);

    mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
    if (PSA::import_key(&attrs, key.data(), key.size(), &key_id) != PSA_SUCCESS) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyImportFailed,
            "Key import failed"));
    }

    const std::size_t output_size =
        PSA_AEAD_ENCRYPT_OUTPUT_SIZE(PSA_KEY_TYPE_AES, PSA_ALG_GCM, plaintext.size());
    SecureBuffer ciphertext(output_size);

    const CryptoByte* aad_ptr  = aad.has_value() ? aad->data() : nullptr;
    const std::size_t  aad_size = aad.has_value() ? aad->size() : 0;

    std::size_t ciphertext_length = 0;
    const psa_status_t status = PSA::aead_encrypt(
        key_id, PSA_ALG_GCM,
        iv->data(), iv->size(),
        aad_ptr, aad_size,
        plaintext.data(), plaintext.size(),
        ciphertext.data(), ciphertext.size(),
        &ciphertext_length);

    PSA::destroy_key(key_id);

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


template<typename PSA = RealPsaBackend>
[[nodiscard]]
auto aes256_gcm_decrypt_impl(  // NOLINT(readability-function-cognitive-complexity)
    const FixedSecureBuffer<aes256_key_size_bytes>& key,
    const AesGcmResult& ciphertext,
    const std::optional<SecureBuffer>& aad = std::nullopt)
    -> std::expected<SecureBuffer, CryptoError>
{
    constexpr std::size_t aes256_key_bits = 256;

    if (PSA::crypto_init() != PSA_SUCCESS) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InitFailed,
            "PSA crypto init failed"));
    }

    psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, aes256_key_bits);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_GCM);

    mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
    if (PSA::import_key(&attrs, key.data(), key.size(), &key_id) != PSA_SUCCESS) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyImportFailed,
            "Key import failed"));
    }

    const CryptoByte* aad_ptr  = aad.has_value() ? aad->data() : nullptr;
    const std::size_t  aad_size = aad.has_value() ? aad->size() : 0;

    const std::size_t plaintext_size =
        PSA_AEAD_DECRYPT_OUTPUT_SIZE(PSA_KEY_TYPE_AES, PSA_ALG_GCM, ciphertext.ciphertext.size());
    SecureBuffer plaintext(plaintext_size);

    std::size_t plaintext_length = 0;
    const psa_status_t status = PSA::aead_decrypt(
        key_id, PSA_ALG_GCM,
        ciphertext.iv.data(), ciphertext.iv.size(),
        aad_ptr, aad_size,
        ciphertext.ciphertext.data(), ciphertext.ciphertext.size(),
        plaintext.data(), plaintext.size(),
        &plaintext_length);

    PSA::destroy_key(key_id);

    if (status != PSA_SUCCESS) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::DecryptionFailed,
            "AES-256-GCM decryption failed"));
    }

    return plaintext;
}


template<typename PSA = RealPsaBackend, SecureBufferLike Plaintext>
[[nodiscard]]
auto chacha20_poly1305_encrypt_impl(  // NOLINT(readability-function-cognitive-complexity)
    const FixedSecureBuffer<chacha20_key_size_bytes>& key,
    const Plaintext& plaintext,
    const std::optional<SecureBuffer>& aad = std::nullopt)
    -> std::expected<ChaCha20Poly1305Result, CryptoError>
{
    constexpr std::size_t chacha20_key_bits = 256;

    if (PSA::crypto_init() != PSA_SUCCESS) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InitFailed,
            "PSA crypto init failed"));
    }

    auto iv = random_bytes_fixed_impl<chacha20_poly1305_iv_size_bytes, PSA>();
    if (!iv.has_value()) {
        return std::unexpected(iv.error());
    }

    psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attrs, PSA_KEY_TYPE_CHACHA20);
    psa_set_key_bits(&attrs, chacha20_key_bits);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_CHACHA20_POLY1305);

    mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
    if (PSA::import_key(&attrs, key.data(), key.size(), &key_id) != PSA_SUCCESS) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyImportFailed,
            "ChaCha20-Poly1305 key import failed"));
    }

    const std::size_t output_size =
        PSA_AEAD_ENCRYPT_OUTPUT_SIZE(PSA_KEY_TYPE_CHACHA20,
                                     PSA_ALG_CHACHA20_POLY1305,
                                     plaintext.size());
    SecureBuffer ciphertext(output_size);

    const CryptoByte* aad_ptr  = aad.has_value() ? aad->data() : nullptr;
    const std::size_t aad_size = aad.has_value() ? aad->size() : 0;

    std::size_t ciphertext_length = 0;
    const psa_status_t status = PSA::aead_encrypt(
        key_id, PSA_ALG_CHACHA20_POLY1305,
        iv->data(), iv->size(),
        aad_ptr, aad_size,
        plaintext.data(), plaintext.size(),
        ciphertext.data(), ciphertext.size(),
        &ciphertext_length);

    PSA::destroy_key(key_id);

    if (status != PSA_SUCCESS) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::EncryptionFailed,
            "ChaCha20-Poly1305 encryption failed"));
    }

    ciphertext.resize(ciphertext_length);
    return ChaCha20Poly1305Result{
        .iv         = std::move(*iv),
        .ciphertext = std::move(ciphertext),
    };
}


template<typename PSA = RealPsaBackend>
[[nodiscard]]
auto chacha20_poly1305_decrypt_impl(  // NOLINT(readability-function-cognitive-complexity)
    const FixedSecureBuffer<chacha20_key_size_bytes>& key,
    const ChaCha20Poly1305Result& ciphertext,
    const std::optional<SecureBuffer>& aad = std::nullopt)
    -> std::expected<SecureBuffer, CryptoError>
{
    constexpr std::size_t chacha20_key_bits = 256;

    if (PSA::crypto_init() != PSA_SUCCESS) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InitFailed,
            "PSA crypto init failed"));
    }

    psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attrs, PSA_KEY_TYPE_CHACHA20);
    psa_set_key_bits(&attrs, chacha20_key_bits);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_CHACHA20_POLY1305);

    mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
    if (PSA::import_key(&attrs, key.data(), key.size(), &key_id) != PSA_SUCCESS) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyImportFailed,
            "ChaCha20-Poly1305 key import failed"));
    }

    const CryptoByte* aad_ptr  = aad.has_value() ? aad->data() : nullptr;
    const std::size_t aad_size = aad.has_value() ? aad->size() : 0;

    const std::size_t plaintext_size =
        PSA_AEAD_DECRYPT_OUTPUT_SIZE(PSA_KEY_TYPE_CHACHA20,
                                     PSA_ALG_CHACHA20_POLY1305,
                                     ciphertext.ciphertext.size());
    SecureBuffer plaintext(plaintext_size);

    std::size_t plaintext_length = 0;
    const psa_status_t status = PSA::aead_decrypt(
        key_id, PSA_ALG_CHACHA20_POLY1305,
        ciphertext.iv.data(), ciphertext.iv.size(),
        aad_ptr, aad_size,
        ciphertext.ciphertext.data(), ciphertext.ciphertext.size(),
        plaintext.data(), plaintext.size(),
        &plaintext_length);

    PSA::destroy_key(key_id);

    if (status != PSA_SUCCESS) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::DecryptionFailed,
            "ChaCha20-Poly1305 decryption failed"));
    }

    plaintext.resize(plaintext_length);
    return plaintext;
}


template<SecureBufferLike Plaintext>
[[nodiscard]]
auto aes256_gcm_encrypt(
    const FixedSecureBuffer<aes256_key_size_bytes>& key,
    const Plaintext& plaintext,
    const std::optional<SecureBuffer>& aad = std::nullopt)
    -> std::expected<AesGcmResult, CryptoError>
{
    return aes256_gcm_encrypt_impl<RealPsaBackend>(key, plaintext, aad);
}

[[nodiscard]]
inline auto aes256_gcm_decrypt(
    const FixedSecureBuffer<aes256_key_size_bytes>& key,
    const AesGcmResult& ciphertext,
    const std::optional<SecureBuffer>& aad = std::nullopt)
    -> std::expected<SecureBuffer, CryptoError>
{
    return aes256_gcm_decrypt_impl<RealPsaBackend>(key, ciphertext, aad);
}

template<SecureBufferLike Plaintext>
[[nodiscard]]
auto chacha20_poly1305_encrypt(
    const FixedSecureBuffer<chacha20_key_size_bytes>& key,
    const Plaintext& plaintext,
    const std::optional<SecureBuffer>& aad = std::nullopt)
    -> std::expected<ChaCha20Poly1305Result, CryptoError>
{
    return chacha20_poly1305_encrypt_impl<RealPsaBackend>(key, plaintext, aad);
}

[[nodiscard]]
inline auto chacha20_poly1305_decrypt(
    const FixedSecureBuffer<chacha20_key_size_bytes>& key,
    const ChaCha20Poly1305Result& ciphertext,
    const std::optional<SecureBuffer>& aad = std::nullopt)
    -> std::expected<SecureBuffer, CryptoError>
{
    return chacha20_poly1305_decrypt_impl<RealPsaBackend>(key, ciphertext, aad);
}
