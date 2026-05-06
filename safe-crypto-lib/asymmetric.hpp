// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Permanence AI

#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>

#include "crypto_error.hpp"
#include "psa_backend.hpp"
#include "secure_buffer.hpp"


enum class RsaKeyBits : std::uint16_t {
    Bits3072 = 3072,
    Bits4096 = 4096,
};


template<RsaKeyBits KB>
struct RsaPublicKey {
    SecureBuffer public_key_der;
};

template<RsaKeyBits KB>
struct RsaKeyPair {
    SecureBuffer private_key_der;
    SecureBuffer public_key_der;
};


template<RsaKeyBits KB, CryptoProvider Provider = DefaultProvider, SecureBufferLike Plaintext>
[[nodiscard]]
auto rsa_oaep_encrypt_impl(  // NOLINT(readability-function-cognitive-complexity)
    const RsaPublicKey<KB>& public_key,
    const Plaintext& plaintext,
    const std::optional<SecureBuffer>& label = std::nullopt)
    -> std::expected<SecureBuffer, CryptoError>
{
    if (Provider::crypto_init() != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InitFailed,
            "PSA crypto init failed"));
    }

    constexpr auto key_bits_val = static_cast<std::size_t>(static_cast<std::uint16_t>(KB));

    auto attrs = Provider::make_rsa_oaep_encrypt_attrs(key_bits_val);

    auto raw_key_id = Provider::null_key_id();
    if (Provider::import_key(&attrs,
                        public_key.public_key_der.data(),
                        public_key.public_key_der.size(),
                        &raw_key_id) != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyImportFailed,
            "RSA public key import failed"));
    }
    const PsaKeyHandle<Provider> key_handle(raw_key_id);

    SecureBuffer ciphertext(Provider::rsa_oaep_encrypt_output_size(key_bits_val));

    const CryptoByte* label_ptr  = label.has_value() ? label->data() : nullptr;
    const std::size_t   label_size = label.has_value() ? label->size() : 0;

    std::size_t ciphertext_length = 0;
    const auto status = Provider::asymmetric_encrypt(
        key_handle.get(),
        Provider::alg_rsa_oaep(),
        plaintext.data(), plaintext.size(),
        label_ptr, label_size,
        ciphertext.data(), ciphertext.size(),
        &ciphertext_length);

    if (status != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::EncryptionFailed,
            "RSA-OAEP encryption failed"));
    }

    ciphertext.resize(ciphertext_length);
    return ciphertext;
}


template<RsaKeyBits KB, CryptoProvider Provider = DefaultProvider, SecureBufferLike Ciphertext>
[[nodiscard]]
auto rsa_oaep_decrypt_impl(  // NOLINT(readability-function-cognitive-complexity)
    const RsaKeyPair<KB>& key_pair,
    const Ciphertext& ciphertext,
    const std::optional<SecureBuffer>& label = std::nullopt)
    -> std::expected<SecureBuffer, CryptoError>
{
    if (Provider::crypto_init() != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InitFailed,
            "PSA crypto init failed"));
    }

    constexpr auto key_bits_val = static_cast<std::size_t>(static_cast<std::uint16_t>(KB));

    auto attrs = Provider::make_rsa_oaep_decrypt_attrs(key_bits_val);

    auto raw_key_id = Provider::null_key_id();
    if (Provider::import_key(&attrs,
                        key_pair.private_key_der.data(),
                        key_pair.private_key_der.size(),
                        &raw_key_id) != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyImportFailed,
            "RSA private key import failed"));
    }
    const PsaKeyHandle<Provider> key_handle(raw_key_id);

    SecureBuffer plaintext(Provider::rsa_oaep_decrypt_output_size(key_bits_val));

    const CryptoByte* label_ptr  = label.has_value() ? label->data() : nullptr;
    const std::size_t   label_size = label.has_value() ? label->size() : 0;

    std::size_t plaintext_length = 0;
    const auto status = Provider::asymmetric_decrypt(
        key_handle.get(),
        Provider::alg_rsa_oaep(),
        ciphertext.data(), ciphertext.size(),
        label_ptr, label_size,
        plaintext.data(), plaintext.size(),
        &plaintext_length);

    if (status != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::DecryptionFailed,
            "RSA-OAEP decryption failed"));
    }

    plaintext.resize(plaintext_length);
    return plaintext;
}


template<RsaKeyBits KB, CryptoProvider Provider = DefaultProvider, SecureBufferLike Message>
[[nodiscard]]
auto rsa_pss_sign_impl(  // NOLINT(readability-function-cognitive-complexity)
    const RsaKeyPair<KB>& key_pair,
    const Message& message)
    -> std::expected<SecureBuffer, CryptoError>
{
    if (Provider::crypto_init() != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InitFailed,
            "PSA crypto init failed"));
    }

    constexpr auto key_bits_val = static_cast<std::size_t>(static_cast<std::uint16_t>(KB));

    auto attrs = Provider::make_rsa_pss_sign_attrs(key_bits_val);

    auto raw_key_id = Provider::null_key_id();
    if (Provider::import_key(&attrs,
                        key_pair.private_key_der.data(),
                        key_pair.private_key_der.size(),
                        &raw_key_id) != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyImportFailed,
            "RSA private key import failed"));
    }
    const PsaKeyHandle<Provider> key_handle(raw_key_id);

    SecureBuffer signature(Provider::rsa_pss_sign_output_size(key_bits_val));

    std::size_t signature_length = 0;
    const auto status = Provider::sign_message(
        key_handle.get(),
        Provider::alg_rsa_pss(),
        message.data(), message.size(),
        signature.data(), signature.size(),
        &signature_length);

    if (status != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::SigningFailed,
            "RSA-PSS signing failed"));
    }

    signature.resize(signature_length);
    return signature;
}


template<RsaKeyBits KB, CryptoProvider Provider = DefaultProvider,
         SecureBufferLike Message, SecureBufferLike Signature>
[[nodiscard]]
auto rsa_pss_verify_impl(  // NOLINT(readability-function-cognitive-complexity)
    const RsaPublicKey<KB>& public_key,
    const Message& message,
    const Signature& signature)
    -> std::expected<bool, CryptoError>
{
    if (Provider::crypto_init() != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InitFailed,
            "PSA crypto init failed"));
    }

    constexpr auto key_bits_val = static_cast<std::size_t>(static_cast<std::uint16_t>(KB));

    auto attrs = Provider::make_rsa_pss_verify_attrs(key_bits_val);

    auto raw_key_id = Provider::null_key_id();
    if (Provider::import_key(&attrs,
                        public_key.public_key_der.data(),
                        public_key.public_key_der.size(),
                        &raw_key_id) != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyImportFailed,
            "RSA public key import failed"));
    }
    const PsaKeyHandle<Provider> key_handle(raw_key_id);

    const auto status = Provider::verify_message(
        key_handle.get(),
        Provider::alg_rsa_pss(),
        message.data(), message.size(),
        signature.data(), signature.size());

    if (status == Provider::err_invalid_sig || status == Provider::err_invalid_arg) {
        return false;
    }
    if (status != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::VerificationFailed,
            "RSA-PSS verification failed"));
    }

    return true;
}


template<RsaKeyBits KB, SecureBufferLike Plaintext>
[[nodiscard]]
auto rsa_oaep_encrypt(
    const RsaPublicKey<KB>& public_key,
    const Plaintext& plaintext,
    const std::optional<SecureBuffer>& label = std::nullopt)
    -> std::expected<SecureBuffer, CryptoError>
{
    return rsa_oaep_encrypt_impl<KB, DefaultProvider>(public_key, plaintext, label);
}

template<RsaKeyBits KB, SecureBufferLike Ciphertext>
[[nodiscard]]
auto rsa_oaep_decrypt(
    const RsaKeyPair<KB>& key_pair,
    const Ciphertext& ciphertext,
    const std::optional<SecureBuffer>& label = std::nullopt)
    -> std::expected<SecureBuffer, CryptoError>
{
    return rsa_oaep_decrypt_impl<KB, DefaultProvider>(key_pair, ciphertext, label);
}

template<RsaKeyBits KB, SecureBufferLike Message>
[[nodiscard]]
auto rsa_pss_sign(
    const RsaKeyPair<KB>& key_pair,
    const Message& message)
    -> std::expected<SecureBuffer, CryptoError>
{
    return rsa_pss_sign_impl<KB, DefaultProvider>(key_pair, message);
}

template<RsaKeyBits KB, SecureBufferLike Message, SecureBufferLike Signature>
[[nodiscard]]
auto rsa_pss_verify(
    const RsaPublicKey<KB>& public_key,
    const Message& message,
    const Signature& signature)
    -> std::expected<bool, CryptoError>
{
    return rsa_pss_verify_impl<KB, DefaultProvider>(public_key, message, signature);
}
