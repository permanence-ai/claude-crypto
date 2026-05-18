// SPDX-License-Identifier: Apache-2.0

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

    auto key_result = Provider::import_key(&attrs, CByteVSpan{key.data(), key.size()});
    if (!key_result.has_value()) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyImportFailed,
            "Key import failed"));
    }
    const PsaKeyHandle<Provider> key_handle(key_result.value());

    auto ct_result = Provider::aead_encrypt(
        key_handle.get(), Provider::alg_aes_gcm(),
        CByteVSpan{iv->data(), iv->size()},
        aad.has_value() ? CByteVSpan{aad->data(), aad->size()} : CByteVSpan{},
        CByteVSpan{plaintext.data(), plaintext.size()});

    if (!ct_result.has_value()) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::EncryptionFailed,
            "AES-256-GCM encryption failed"));
    }

    return AesGcmResult{
        .iv         = std::move(*iv),
        .ciphertext = std::move(ct_result).value(),
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

    auto key_result = Provider::import_key(&attrs, CByteVSpan{key.data(), key.size()});
    if (!key_result.has_value()) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyImportFailed,
            "Key import failed"));
    }
    const PsaKeyHandle<Provider> key_handle(key_result.value());

    auto pt_result = Provider::aead_decrypt(
        key_handle.get(), Provider::alg_aes_gcm(),
        CByteVSpan{ciphertext.iv.data(), ciphertext.iv.size()},
        aad.has_value() ? CByteVSpan{aad->data(), aad->size()} : CByteVSpan{},
        CByteVSpan{ciphertext.ciphertext.data(), ciphertext.ciphertext.size()});

    if (!pt_result.has_value()) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::DecryptionFailed,
            "AES-256-GCM decryption failed"));
    }

    return std::move(pt_result).value();
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

    auto key_result = Provider::import_key(&attrs, CByteVSpan{key.data(), key.size()});
    if (!key_result.has_value()) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyImportFailed,
            "ChaCha20-Poly1305 key import failed"));
    }
    const PsaKeyHandle<Provider> key_handle(key_result.value());

    auto ct_result = Provider::aead_encrypt(
        key_handle.get(), Provider::alg_chacha20_poly1305(),
        CByteVSpan{iv->data(), iv->size()},
        aad.has_value() ? CByteVSpan{aad->data(), aad->size()} : CByteVSpan{},
        CByteVSpan{plaintext.data(), plaintext.size()});

    if (!ct_result.has_value()) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::EncryptionFailed,
            "ChaCha20-Poly1305 encryption failed"));
    }

    return ChaCha20Poly1305Result{
        .iv         = std::move(*iv),
        .ciphertext = std::move(ct_result).value(),
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

    auto key_result = Provider::import_key(&attrs, CByteVSpan{key.data(), key.size()});
    if (!key_result.has_value()) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyImportFailed,
            "ChaCha20-Poly1305 key import failed"));
    }
    const PsaKeyHandle<Provider> key_handle(key_result.value());

    auto pt_result = Provider::aead_decrypt(
        key_handle.get(), Provider::alg_chacha20_poly1305(),
        CByteVSpan{ciphertext.iv.data(), ciphertext.iv.size()},
        aad.has_value() ? CByteVSpan{aad->data(), aad->size()} : CByteVSpan{},
        CByteVSpan{ciphertext.ciphertext.data(), ciphertext.ciphertext.size()});

    if (!pt_result.has_value()) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::DecryptionFailed,
            "ChaCha20-Poly1305 decryption failed"));
    }

    return std::move(pt_result).value();
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
