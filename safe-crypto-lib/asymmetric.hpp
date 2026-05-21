// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>

#include "crypto_error.hpp"
#include "crypto_log.hpp"
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

    auto key_result = Provider::import_key(&attrs,
                        CByteVSpan{public_key.public_key_der.data(),
                                   public_key.public_key_der.size()});
    if (!key_result.has_value()) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyImportFailed,
            "RSA public key import failed"));
    }
    const PsaKeyHandle<Provider> key_handle(key_result.value());

    auto ct_result = Provider::asymmetric_encrypt(
        key_handle.get(),
        Provider::alg_rsa_oaep(),
        CByteVSpan{plaintext.data(), plaintext.size()},
        label.has_value() ? CByteVSpan{label->data(), label->size()} : CByteVSpan{});

    if (!ct_result.has_value()) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::EncryptionFailed,
            "RSA-OAEP encryption failed"));
    }

    return std::move(ct_result).value();
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

    auto key_result = Provider::import_key(&attrs,
                        CByteVSpan{key_pair.private_key_der.data(),
                                   key_pair.private_key_der.size()});
    if (!key_result.has_value()) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyImportFailed,
            "RSA private key import failed"));
    }
    const PsaKeyHandle<Provider> key_handle(key_result.value());

    auto pt_result = Provider::asymmetric_decrypt(
        key_handle.get(),
        Provider::alg_rsa_oaep(),
        CByteVSpan{ciphertext.data(), ciphertext.size()},
        label.has_value() ? CByteVSpan{label->data(), label->size()} : CByteVSpan{});

    if (!pt_result.has_value()) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::DecryptionFailed,
            "RSA-OAEP decryption failed"));
    }

    return std::move(pt_result).value();
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

    auto key_result = Provider::import_key(&attrs,
                        CByteVSpan{key_pair.private_key_der.data(),
                                   key_pair.private_key_der.size()});
    if (!key_result.has_value()) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyImportFailed,
            "RSA private key import failed"));
    }
    const PsaKeyHandle<Provider> key_handle(key_result.value());

    auto sig_result = Provider::sign_message(
        key_handle.get(),
        Provider::alg_rsa_pss(),
        CByteVSpan{message.data(), message.size()});

    if (!sig_result.has_value()) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::SigningFailed,
            "RSA-PSS signing failed"));
    }

    return std::move(sig_result).value();
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

    auto key_result = Provider::import_key(&attrs,
                        CByteVSpan{public_key.public_key_der.data(),
                                   public_key.public_key_der.size()});
    if (!key_result.has_value()) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyImportFailed,
            "RSA public key import failed"));
    }
    const PsaKeyHandle<Provider> key_handle(key_result.value());

    const auto status = Provider::verify_message(
        key_handle.get(),
        Provider::alg_rsa_pss(),
        CByteVSpan{message.data(), message.size()},
        CByteVSpan{signature.data(), signature.size()});

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
    if (crypto_log_enabled(CryptoLogLevel::Debug)) {
        crypto_log(CryptoLogLevel::Debug,
            crypto_log_detail::msg("rsa_oaep_encrypt", "plaintext", plaintext.size()));
    }
    auto result = rsa_oaep_encrypt_impl<KB, DefaultProvider>(public_key, plaintext, label);
    if (!result.has_value()) {
        crypto_log(CryptoLogLevel::Error, "rsa_oaep_encrypt: " + result.error().message());
    } else if (crypto_log_enabled(CryptoLogLevel::Debug)) {
        crypto_log(CryptoLogLevel::Debug,
            crypto_log_detail::msg("rsa_oaep_encrypt", "ciphertext", result->size()));
    }
    return result;
}

template<RsaKeyBits KB, SecureBufferLike Ciphertext>
[[nodiscard]]
auto rsa_oaep_decrypt(
    const RsaKeyPair<KB>& key_pair,
    const Ciphertext& ciphertext,
    const std::optional<SecureBuffer>& label = std::nullopt)
    -> std::expected<SecureBuffer, CryptoError>
{
    if (crypto_log_enabled(CryptoLogLevel::Debug)) {
        crypto_log(CryptoLogLevel::Debug,
            crypto_log_detail::msg("rsa_oaep_decrypt", "ciphertext", ciphertext.size()));
    }
    auto result = rsa_oaep_decrypt_impl<KB, DefaultProvider>(key_pair, ciphertext, label);
    if (!result.has_value()) {
        crypto_log(CryptoLogLevel::Error, "rsa_oaep_decrypt: " + result.error().message());
    } else if (crypto_log_enabled(CryptoLogLevel::Debug)) {
        crypto_log(CryptoLogLevel::Debug,
            crypto_log_detail::msg("rsa_oaep_decrypt", "plaintext", result->size()));
    }
    return result;
}

template<RsaKeyBits KB, SecureBufferLike Message>
[[nodiscard]]
auto rsa_pss_sign(
    const RsaKeyPair<KB>& key_pair,
    const Message& message)
    -> std::expected<SecureBuffer, CryptoError>
{
    if (crypto_log_enabled(CryptoLogLevel::Debug)) {
        crypto_log(CryptoLogLevel::Debug,
            crypto_log_detail::msg("rsa_pss_sign", "msg", message.size()));
    }
    auto result = rsa_pss_sign_impl<KB, DefaultProvider>(key_pair, message);
    if (!result.has_value()) {
        crypto_log(CryptoLogLevel::Error, "rsa_pss_sign: " + result.error().message());
    } else if (crypto_log_enabled(CryptoLogLevel::Debug)) {
        crypto_log(CryptoLogLevel::Debug,
            crypto_log_detail::msg("rsa_pss_sign", "sig", result->size()));
    }
    return result;
}

template<RsaKeyBits KB, SecureBufferLike Message, SecureBufferLike Signature>
[[nodiscard]]
auto rsa_pss_verify(
    const RsaPublicKey<KB>& public_key,
    const Message& message,
    const Signature& signature)
    -> std::expected<bool, CryptoError>
{
    if (crypto_log_enabled(CryptoLogLevel::Debug)) {
        crypto_log(CryptoLogLevel::Debug,
            crypto_log_detail::msg("rsa_pss_verify", "msg", message.size(), "sig", signature.size()));
    }
    auto result = rsa_pss_verify_impl<KB, DefaultProvider>(public_key, message, signature);
    if (!result.has_value()) {
        crypto_log(CryptoLogLevel::Error, "rsa_pss_verify: " + result.error().message());
    } else if (crypto_log_enabled(CryptoLogLevel::Debug)) {
        crypto_log(CryptoLogLevel::Debug,
            result.value() ? "rsa_pss_verify: ok" : "rsa_pss_verify: mismatch");
    }
    return result;
}
