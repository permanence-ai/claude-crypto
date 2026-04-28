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


template<RsaKeyBits KB, CryptoProvider Provider = RealPsaBackend, SecureBufferLike Plaintext>
[[nodiscard]]
auto rsa_oaep_encrypt_impl(  // NOLINT(readability-function-cognitive-complexity)
    const RsaPublicKey<KB>& public_key,
    const Plaintext& plaintext,
    const std::optional<SecureBuffer>& label = std::nullopt)
    -> std::expected<SecureBuffer, CryptoError>
{
    if (Provider::crypto_init() != PSA_SUCCESS) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InitFailed,
            "PSA crypto init failed"));
    }

    constexpr auto key_bits_val = static_cast<psa_key_bits_t>(static_cast<std::uint16_t>(KB));

    psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attrs, PSA_KEY_TYPE_RSA_PUBLIC_KEY);
    psa_set_key_bits(&attrs, key_bits_val);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_RSA_OAEP(PSA_ALG_SHA_384));

    mbedtls_svc_key_id_t raw_key_id = MBEDTLS_SVC_KEY_ID_INIT;
    if (Provider::import_key(&attrs,
                        public_key.public_key_der.data(),
                        public_key.public_key_der.size(),
                        &raw_key_id) != PSA_SUCCESS) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyImportFailed,
            "RSA public key import failed"));
    }
    const PsaKeyHandle<Provider> key_handle(raw_key_id);

    const std::size_t output_size =
        PSA_ASYMMETRIC_ENCRYPT_OUTPUT_SIZE(PSA_KEY_TYPE_RSA_PUBLIC_KEY,
                                           key_bits_val,
                                           PSA_ALG_RSA_OAEP(PSA_ALG_SHA_384));
    SecureBuffer ciphertext(output_size);

    const CryptoByte* label_ptr  = label.has_value() ? label->data() : nullptr;
    const std::size_t   label_size = label.has_value() ? label->size() : 0;

    std::size_t ciphertext_length = 0;
    const psa_status_t status = Provider::asymmetric_encrypt(
        key_handle.get(),
        PSA_ALG_RSA_OAEP(PSA_ALG_SHA_384),
        plaintext.data(), plaintext.size(),
        label_ptr, label_size,
        ciphertext.data(), ciphertext.size(),
        &ciphertext_length);

    if (status != PSA_SUCCESS) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::EncryptionFailed,
            "RSA-OAEP encryption failed"));
    }

    ciphertext.resize(ciphertext_length);
    return ciphertext;
}


template<RsaKeyBits KB, CryptoProvider Provider = RealPsaBackend, SecureBufferLike Ciphertext>
[[nodiscard]]
auto rsa_oaep_decrypt_impl(  // NOLINT(readability-function-cognitive-complexity)
    const RsaKeyPair<KB>& key_pair,
    const Ciphertext& ciphertext,
    const std::optional<SecureBuffer>& label = std::nullopt)
    -> std::expected<SecureBuffer, CryptoError>
{
    if (Provider::crypto_init() != PSA_SUCCESS) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InitFailed,
            "PSA crypto init failed"));
    }

    constexpr auto key_bits_val = static_cast<psa_key_bits_t>(static_cast<std::uint16_t>(KB));

    psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attrs, PSA_KEY_TYPE_RSA_KEY_PAIR);
    psa_set_key_bits(&attrs, key_bits_val);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_RSA_OAEP(PSA_ALG_SHA_384));

    mbedtls_svc_key_id_t raw_key_id = MBEDTLS_SVC_KEY_ID_INIT;
    if (Provider::import_key(&attrs,
                        key_pair.private_key_der.data(),
                        key_pair.private_key_der.size(),
                        &raw_key_id) != PSA_SUCCESS) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyImportFailed,
            "RSA private key import failed"));
    }
    const PsaKeyHandle<Provider> key_handle(raw_key_id);

    const std::size_t output_size =
        PSA_ASYMMETRIC_DECRYPT_OUTPUT_SIZE(PSA_KEY_TYPE_RSA_KEY_PAIR,
                                           key_bits_val,
                                           PSA_ALG_RSA_OAEP(PSA_ALG_SHA_384));
    SecureBuffer plaintext(output_size);

    const CryptoByte* label_ptr  = label.has_value() ? label->data() : nullptr;
    const std::size_t   label_size = label.has_value() ? label->size() : 0;

    std::size_t plaintext_length = 0;
    const psa_status_t status = Provider::asymmetric_decrypt(
        key_handle.get(),
        PSA_ALG_RSA_OAEP(PSA_ALG_SHA_384),
        ciphertext.data(), ciphertext.size(),
        label_ptr, label_size,
        plaintext.data(), plaintext.size(),
        &plaintext_length);

    if (status != PSA_SUCCESS) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::DecryptionFailed,
            "RSA-OAEP decryption failed"));
    }

    plaintext.resize(plaintext_length);
    return plaintext;
}


template<RsaKeyBits KB, CryptoProvider Provider = RealPsaBackend, SecureBufferLike Message>
[[nodiscard]]
auto rsa_pss_sign_impl(  // NOLINT(readability-function-cognitive-complexity)
    const RsaKeyPair<KB>& key_pair,
    const Message& message)
    -> std::expected<SecureBuffer, CryptoError>
{
    if (Provider::crypto_init() != PSA_SUCCESS) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InitFailed,
            "PSA crypto init failed"));
    }

    constexpr auto key_bits_val = static_cast<psa_key_bits_t>(static_cast<std::uint16_t>(KB));

    psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attrs, PSA_KEY_TYPE_RSA_KEY_PAIR);
    psa_set_key_bits(&attrs, key_bits_val);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attrs, PSA_ALG_RSA_PSS(PSA_ALG_SHA_384));

    mbedtls_svc_key_id_t raw_key_id = MBEDTLS_SVC_KEY_ID_INIT;
    if (Provider::import_key(&attrs,
                        key_pair.private_key_der.data(),
                        key_pair.private_key_der.size(),
                        &raw_key_id) != PSA_SUCCESS) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyImportFailed,
            "RSA private key import failed"));
    }
    const PsaKeyHandle<Provider> key_handle(raw_key_id);

    const std::size_t signature_size =
        PSA_SIGN_OUTPUT_SIZE(PSA_KEY_TYPE_RSA_KEY_PAIR,
                             key_bits_val,
                             PSA_ALG_RSA_PSS(PSA_ALG_SHA_384));
    SecureBuffer signature(signature_size);

    std::size_t signature_length = 0;
    const psa_status_t status = Provider::sign_message(
        key_handle.get(),
        PSA_ALG_RSA_PSS(PSA_ALG_SHA_384),
        message.data(), message.size(),
        signature.data(), signature.size(),
        &signature_length);

    if (status != PSA_SUCCESS) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::SigningFailed,
            "RSA-PSS signing failed"));
    }

    signature.resize(signature_length);
    return signature;
}


template<RsaKeyBits KB, CryptoProvider Provider = RealPsaBackend,
         SecureBufferLike Message, SecureBufferLike Signature>
[[nodiscard]]
auto rsa_pss_verify_impl(  // NOLINT(readability-function-cognitive-complexity)
    const RsaPublicKey<KB>& public_key,
    const Message& message,
    const Signature& signature)
    -> std::expected<bool, CryptoError>
{
    if (Provider::crypto_init() != PSA_SUCCESS) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InitFailed,
            "PSA crypto init failed"));
    }

    constexpr auto key_bits_val = static_cast<psa_key_bits_t>(static_cast<std::uint16_t>(KB));

    psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attrs, PSA_KEY_TYPE_RSA_PUBLIC_KEY);
    psa_set_key_bits(&attrs, key_bits_val);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(&attrs, PSA_ALG_RSA_PSS(PSA_ALG_SHA_384));

    mbedtls_svc_key_id_t raw_key_id = MBEDTLS_SVC_KEY_ID_INIT;
    if (Provider::import_key(&attrs,
                        public_key.public_key_der.data(),
                        public_key.public_key_der.size(),
                        &raw_key_id) != PSA_SUCCESS) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyImportFailed,
            "RSA public key import failed"));
    }
    const PsaKeyHandle<Provider> key_handle(raw_key_id);

    const psa_status_t status = Provider::verify_message(
        key_handle.get(),
        PSA_ALG_RSA_PSS(PSA_ALG_SHA_384),
        message.data(), message.size(),
        signature.data(), signature.size());

    if (status == PSA_ERROR_INVALID_SIGNATURE || status == PSA_ERROR_INVALID_ARGUMENT) {
        return false;
    }
    if (status != PSA_SUCCESS) {
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
    return rsa_oaep_encrypt_impl<KB, RealPsaBackend>(public_key, plaintext, label);
}

template<RsaKeyBits KB, SecureBufferLike Ciphertext>
[[nodiscard]]
auto rsa_oaep_decrypt(
    const RsaKeyPair<KB>& key_pair,
    const Ciphertext& ciphertext,
    const std::optional<SecureBuffer>& label = std::nullopt)
    -> std::expected<SecureBuffer, CryptoError>
{
    return rsa_oaep_decrypt_impl<KB, RealPsaBackend>(key_pair, ciphertext, label);
}

template<RsaKeyBits KB, SecureBufferLike Message>
[[nodiscard]]
auto rsa_pss_sign(
    const RsaKeyPair<KB>& key_pair,
    const Message& message)
    -> std::expected<SecureBuffer, CryptoError>
{
    return rsa_pss_sign_impl<KB, RealPsaBackend>(key_pair, message);
}

template<RsaKeyBits KB, SecureBufferLike Message, SecureBufferLike Signature>
[[nodiscard]]
auto rsa_pss_verify(
    const RsaPublicKey<KB>& public_key,
    const Message& message,
    const Signature& signature)
    -> std::expected<bool, CryptoError>
{
    return rsa_pss_verify_impl<KB, RealPsaBackend>(public_key, message, signature);
}
