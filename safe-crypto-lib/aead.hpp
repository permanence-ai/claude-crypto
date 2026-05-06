// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Permanence AI

#pragma once

#include <cstddef>
#include <expected>
#include <optional>

#include "crypto_error.hpp"
#include "defs.hpp"
#include "psa_backend.hpp"
#include "random.hpp"
#include "secure_buffer.hpp"


constexpr std::size_t aes_gcm_iv_size_bytes           = 12;
constexpr std::size_t chacha20_poly1305_iv_size_bytes  = 12;


struct AesGcmResult {
    FixedSecureBuffer<aes_gcm_iv_size_bytes> iv;
    SecureBuffer                             ciphertext;
};


struct ChaCha20Poly1305Result {
    FixedSecureBuffer<chacha20_poly1305_iv_size_bytes> iv;
    SecureBuffer                                       ciphertext;
};


template<CryptoProvider Provider = DefaultProvider, SecureBufferLike Plaintext>
[[nodiscard]]
auto aes256_gcm_encrypt_impl(  // NOLINT(readability-function-cognitive-complexity)
    const FixedSecureBuffer<aes256_key_size_bytes>& key,
    const Plaintext& plaintext,
    const std::optional<SecureBuffer>& aad = std::nullopt)
    -> std::expected<AesGcmResult, CryptoError>
{
    if (Provider::crypto_init() != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InitFailed,
            "PSA crypto init failed"));
    }

    auto iv = random_bytes_fixed_impl<aes_gcm_iv_size_bytes, Provider>();
    if (!iv.has_value()) {
        return std::unexpected(iv.error());
    }

    auto attrs = Provider::make_aes256_gcm_encrypt_attrs();

    auto raw_key_id = Provider::null_key_id();
    if (Provider::import_key(&attrs, key.data(), key.size(), &raw_key_id) != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyImportFailed,
            "Key import failed"));
    }
    const PsaKeyHandle<Provider> key_handle(raw_key_id);

    SecureBuffer ciphertext(Provider::aes_gcm_encrypt_output_size(plaintext.size()));

    const CryptoByte* aad_ptr  = aad.has_value() ? aad->data() : nullptr;
    const std::size_t  aad_size = aad.has_value() ? aad->size() : 0;

    std::size_t ciphertext_length = 0;
    const auto status = Provider::aead_encrypt(
        key_handle.get(), Provider::alg_aes_gcm(),
        iv->data(), iv->size(),
        aad_ptr, aad_size,
        plaintext.data(), plaintext.size(),
        ciphertext.data(), ciphertext.size(),
        &ciphertext_length);

    if (status != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::EncryptionFailed,
            "AES-256-GCM encryption failed"));
    }

    return AesGcmResult{
        .iv         = std::move(*iv),
        .ciphertext = std::move(ciphertext),
    };
}


template<CryptoProvider Provider = DefaultProvider>
[[nodiscard]]
auto aes256_gcm_decrypt_impl(  // NOLINT(readability-function-cognitive-complexity)
    const FixedSecureBuffer<aes256_key_size_bytes>& key,
    const AesGcmResult& ciphertext,
    const std::optional<SecureBuffer>& aad = std::nullopt)
    -> std::expected<SecureBuffer, CryptoError>
{
    if (Provider::crypto_init() != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InitFailed,
            "PSA crypto init failed"));
    }

    auto attrs = Provider::make_aes256_gcm_decrypt_attrs();

    auto raw_key_id = Provider::null_key_id();
    if (Provider::import_key(&attrs, key.data(), key.size(), &raw_key_id) != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyImportFailed,
            "Key import failed"));
    }
    const PsaKeyHandle<Provider> key_handle(raw_key_id);

    const CryptoByte* aad_ptr  = aad.has_value() ? aad->data() : nullptr;
    const std::size_t  aad_size = aad.has_value() ? aad->size() : 0;

    SecureBuffer plaintext(Provider::aes_gcm_decrypt_output_size(ciphertext.ciphertext.size()));

    std::size_t plaintext_length = 0;
    const auto status = Provider::aead_decrypt(
        key_handle.get(), Provider::alg_aes_gcm(),
        ciphertext.iv.data(), ciphertext.iv.size(),
        aad_ptr, aad_size,
        ciphertext.ciphertext.data(), ciphertext.ciphertext.size(),
        plaintext.data(), plaintext.size(),
        &plaintext_length);

    if (status != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::DecryptionFailed,
            "AES-256-GCM decryption failed"));
    }

    return plaintext;
}


template<CryptoProvider Provider = DefaultProvider, SecureBufferLike Plaintext>
[[nodiscard]]
auto chacha20_poly1305_encrypt_impl(  // NOLINT(readability-function-cognitive-complexity)
    const FixedSecureBuffer<chacha20_key_size_bytes>& key,
    const Plaintext& plaintext,
    const std::optional<SecureBuffer>& aad = std::nullopt)
    -> std::expected<ChaCha20Poly1305Result, CryptoError>
{
    if (Provider::crypto_init() != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InitFailed,
            "PSA crypto init failed"));
    }

    auto iv = random_bytes_fixed_impl<chacha20_poly1305_iv_size_bytes, Provider>();
    if (!iv.has_value()) {
        return std::unexpected(iv.error());
    }

    auto attrs = Provider::make_chacha20_poly1305_encrypt_attrs();

    auto raw_key_id = Provider::null_key_id();
    if (Provider::import_key(&attrs, key.data(), key.size(), &raw_key_id) != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyImportFailed,
            "ChaCha20-Poly1305 key import failed"));
    }
    const PsaKeyHandle<Provider> key_handle(raw_key_id);

    SecureBuffer ciphertext(Provider::chacha20_encrypt_output_size(plaintext.size()));

    const CryptoByte* aad_ptr  = aad.has_value() ? aad->data() : nullptr;
    const std::size_t aad_size = aad.has_value() ? aad->size() : 0;

    std::size_t ciphertext_length = 0;
    const auto status = Provider::aead_encrypt(
        key_handle.get(), Provider::alg_chacha20_poly1305(),
        iv->data(), iv->size(),
        aad_ptr, aad_size,
        plaintext.data(), plaintext.size(),
        ciphertext.data(), ciphertext.size(),
        &ciphertext_length);

    if (status != Provider::ok) {
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


template<CryptoProvider Provider = DefaultProvider>
[[nodiscard]]
auto chacha20_poly1305_decrypt_impl(  // NOLINT(readability-function-cognitive-complexity)
    const FixedSecureBuffer<chacha20_key_size_bytes>& key,
    const ChaCha20Poly1305Result& ciphertext,
    const std::optional<SecureBuffer>& aad = std::nullopt)
    -> std::expected<SecureBuffer, CryptoError>
{
    if (Provider::crypto_init() != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InitFailed,
            "PSA crypto init failed"));
    }

    auto attrs = Provider::make_chacha20_poly1305_decrypt_attrs();

    auto raw_key_id = Provider::null_key_id();
    if (Provider::import_key(&attrs, key.data(), key.size(), &raw_key_id) != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyImportFailed,
            "ChaCha20-Poly1305 key import failed"));
    }
    const PsaKeyHandle<Provider> key_handle(raw_key_id);

    const CryptoByte* aad_ptr  = aad.has_value() ? aad->data() : nullptr;
    const std::size_t aad_size = aad.has_value() ? aad->size() : 0;

    SecureBuffer plaintext(Provider::chacha20_decrypt_output_size(ciphertext.ciphertext.size()));

    std::size_t plaintext_length = 0;
    const auto status = Provider::aead_decrypt(
        key_handle.get(), Provider::alg_chacha20_poly1305(),
        ciphertext.iv.data(), ciphertext.iv.size(),
        aad_ptr, aad_size,
        ciphertext.ciphertext.data(), ciphertext.ciphertext.size(),
        plaintext.data(), plaintext.size(),
        &plaintext_length);

    if (status != Provider::ok) {
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
    return aes256_gcm_encrypt_impl<DefaultProvider>(key, plaintext, aad);
}

[[nodiscard]]
inline auto aes256_gcm_decrypt(
    const FixedSecureBuffer<aes256_key_size_bytes>& key,
    const AesGcmResult& ciphertext,
    const std::optional<SecureBuffer>& aad = std::nullopt)
    -> std::expected<SecureBuffer, CryptoError>
{
    return aes256_gcm_decrypt_impl<DefaultProvider>(key, ciphertext, aad);
}

template<SecureBufferLike Plaintext>
[[nodiscard]]
auto chacha20_poly1305_encrypt(
    const FixedSecureBuffer<chacha20_key_size_bytes>& key,
    const Plaintext& plaintext,
    const std::optional<SecureBuffer>& aad = std::nullopt)
    -> std::expected<ChaCha20Poly1305Result, CryptoError>
{
    return chacha20_poly1305_encrypt_impl<DefaultProvider>(key, plaintext, aad);
}

[[nodiscard]]
inline auto chacha20_poly1305_decrypt(
    const FixedSecureBuffer<chacha20_key_size_bytes>& key,
    const ChaCha20Poly1305Result& ciphertext,
    const std::optional<SecureBuffer>& aad = std::nullopt)
    -> std::expected<SecureBuffer, CryptoError>
{
    return chacha20_poly1305_decrypt_impl<DefaultProvider>(key, ciphertext, aad);
}
