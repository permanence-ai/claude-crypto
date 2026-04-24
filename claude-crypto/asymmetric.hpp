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
#include "secure_buffer.hpp"


enum class RsaKeyBits : psa_key_bits_t {
    Bits3072 = 3072,
    Bits4096 = 4096,
};


struct RsaKeyPair {
    SecureBuffer private_key_der;
    SecureBuffer public_key_der;
    RsaKeyBits   key_bits;
};


[[nodiscard]]
inline auto rsa_oaep_encrypt(  // NOLINT(readability-function-cognitive-complexity)
    const RsaKeyPair& key_pair,
    const SecureBuffer& plaintext,
    const std::optional<SecureBuffer>& label = std::nullopt)
    -> std::expected<SecureBuffer, CryptoError>
{
    if (psa_crypto_init() != PSA_SUCCESS) {
        return std::unexpected(CryptoError("PSA crypto init failed"));
    }

    const auto key_bits_val = static_cast<psa_key_bits_t>(key_pair.key_bits);

    psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attrs, PSA_KEY_TYPE_RSA_PUBLIC_KEY);
    psa_set_key_bits(&attrs, key_bits_val);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_RSA_OAEP(PSA_ALG_SHA_384));

    mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
    if (psa_import_key(&attrs,
                       key_pair.public_key_der.data(),
                       key_pair.public_key_der.size(),
                       &key_id) != PSA_SUCCESS) {
        return std::unexpected(CryptoError("RSA public key import failed"));
    }

    const std::size_t output_size =
        PSA_ASYMMETRIC_ENCRYPT_OUTPUT_SIZE(PSA_KEY_TYPE_RSA_PUBLIC_KEY,
                                           key_bits_val,
                                           PSA_ALG_RSA_OAEP(PSA_ALG_SHA_384));
    SecureBuffer ciphertext(output_size);

    const std::uint8_t* label_ptr  = label.has_value() ? label->data() : nullptr;
    const std::size_t   label_size = label.has_value() ? label->size() : 0;

    std::size_t ciphertext_length = 0;
    const psa_status_t status = psa_asymmetric_encrypt(
        key_id,
        PSA_ALG_RSA_OAEP(PSA_ALG_SHA_384),
        plaintext.data(), plaintext.size(),
        label_ptr, label_size,
        ciphertext.data(), ciphertext.size(),
        &ciphertext_length);

    psa_destroy_key(key_id);

    if (status != PSA_SUCCESS) {
        return std::unexpected(CryptoError("RSA-OAEP encryption failed"));
    }

    ciphertext.resize(ciphertext_length);
    return ciphertext;
}


[[nodiscard]]
inline auto rsa_oaep_decrypt(  // NOLINT(readability-function-cognitive-complexity)
    const RsaKeyPair& key_pair,
    const SecureBuffer& ciphertext,
    const std::optional<SecureBuffer>& label = std::nullopt)
    -> std::expected<SecureBuffer, CryptoError>
{
    if (psa_crypto_init() != PSA_SUCCESS) {
        return std::unexpected(CryptoError("PSA crypto init failed"));
    }

    const auto key_bits_val = static_cast<psa_key_bits_t>(key_pair.key_bits);

    psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attrs, PSA_KEY_TYPE_RSA_KEY_PAIR);
    psa_set_key_bits(&attrs, key_bits_val);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_RSA_OAEP(PSA_ALG_SHA_384));

    mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
    if (psa_import_key(&attrs,
                       key_pair.private_key_der.data(),
                       key_pair.private_key_der.size(),
                       &key_id) != PSA_SUCCESS) {
        return std::unexpected(CryptoError("RSA private key import failed"));
    }

    const std::size_t output_size =
        PSA_ASYMMETRIC_DECRYPT_OUTPUT_SIZE(PSA_KEY_TYPE_RSA_KEY_PAIR,
                                           key_bits_val,
                                           PSA_ALG_RSA_OAEP(PSA_ALG_SHA_384));
    SecureBuffer plaintext(output_size);

    const std::uint8_t* label_ptr  = label.has_value() ? label->data() : nullptr;
    const std::size_t   label_size = label.has_value() ? label->size() : 0;

    std::size_t plaintext_length = 0;
    const psa_status_t status = psa_asymmetric_decrypt(
        key_id,
        PSA_ALG_RSA_OAEP(PSA_ALG_SHA_384),
        ciphertext.data(), ciphertext.size(),
        label_ptr, label_size,
        plaintext.data(), plaintext.size(),
        &plaintext_length);

    psa_destroy_key(key_id);

    if (status != PSA_SUCCESS) {
        return std::unexpected(CryptoError("RSA-OAEP decryption failed"));
    }

    plaintext.resize(plaintext_length);
    return plaintext;
}


[[nodiscard]]
inline auto rsa_pss_sign(  // NOLINT(readability-function-cognitive-complexity)
    const RsaKeyPair& key_pair,
    const SecureBuffer& message)
    -> std::expected<SecureBuffer, CryptoError>
{
    if (psa_crypto_init() != PSA_SUCCESS) {
        return std::unexpected(CryptoError("PSA crypto init failed"));
    }

    const auto key_bits_val = static_cast<psa_key_bits_t>(key_pair.key_bits);

    psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attrs, PSA_KEY_TYPE_RSA_KEY_PAIR);
    psa_set_key_bits(&attrs, key_bits_val);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attrs, PSA_ALG_RSA_PSS(PSA_ALG_SHA_384));

    mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
    if (psa_import_key(&attrs,
                       key_pair.private_key_der.data(),
                       key_pair.private_key_der.size(),
                       &key_id) != PSA_SUCCESS) {
        return std::unexpected(CryptoError("RSA private key import failed"));
    }

    const std::size_t signature_size =
        PSA_SIGN_OUTPUT_SIZE(PSA_KEY_TYPE_RSA_KEY_PAIR,
                             key_bits_val,
                             PSA_ALG_RSA_PSS(PSA_ALG_SHA_384));
    SecureBuffer signature(signature_size);

    std::size_t signature_length = 0;
    const psa_status_t status = psa_sign_message(
        key_id,
        PSA_ALG_RSA_PSS(PSA_ALG_SHA_384),
        message.data(), message.size(),
        signature.data(), signature.size(),
        &signature_length);

    psa_destroy_key(key_id);

    if (status != PSA_SUCCESS) {
        return std::unexpected(CryptoError("RSA-PSS signing failed"));
    }

    signature.resize(signature_length);
    return signature;
}


[[nodiscard]]
inline auto rsa_pss_verify(  // NOLINT(readability-function-cognitive-complexity)
    const RsaKeyPair& key_pair,
    const SecureBuffer& message,
    const SecureBuffer& signature)
    -> std::expected<void, CryptoError>
{
    if (psa_crypto_init() != PSA_SUCCESS) {
        return std::unexpected(CryptoError("PSA crypto init failed"));
    }

    const auto key_bits_val = static_cast<psa_key_bits_t>(key_pair.key_bits);

    psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attrs, PSA_KEY_TYPE_RSA_PUBLIC_KEY);
    psa_set_key_bits(&attrs, key_bits_val);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(&attrs, PSA_ALG_RSA_PSS(PSA_ALG_SHA_384));

    mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
    if (psa_import_key(&attrs,
                       key_pair.public_key_der.data(),
                       key_pair.public_key_der.size(),
                       &key_id) != PSA_SUCCESS) {
        return std::unexpected(CryptoError("RSA public key import failed"));
    }

    const psa_status_t status = psa_verify_message(
        key_id,
        PSA_ALG_RSA_PSS(PSA_ALG_SHA_384),
        message.data(), message.size(),
        signature.data(), signature.size());

    psa_destroy_key(key_id);

    if (status != PSA_SUCCESS) {
        return std::unexpected(CryptoError("RSA-PSS verification failed"));
    }

    return {};
}
