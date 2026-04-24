/*
Copyright Permanence AI, 2026. All rights reserved.

*/

#pragma once

#include <cstddef>
#include <expected>

#include <psa/crypto.h>
#include <psa/crypto_sizes.h>
#include <psa/crypto_values.h>

#include "crypto_error.hpp"
#include "secure_buffer.hpp"


[[nodiscard]]
inline auto hmac_sha384_generate(const SecureBuffer& key,  // NOLINT(readability-function-cognitive-complexity)
                                 const SecureBuffer& message)
    -> std::expected<SecureBuffer, CryptoError>
{
    if (psa_crypto_init() != PSA_SUCCESS) {
        return std::unexpected(CryptoError("PSA crypto init failed"));
    }

    psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attrs, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&attrs, static_cast<psa_key_bits_t>(key.size() * 8));
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attrs, PSA_ALG_HMAC(PSA_ALG_SHA_384));

    mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
    if (psa_import_key(&attrs, key.data(), key.size(), &key_id) != PSA_SUCCESS) {
        return std::unexpected(CryptoError("Key import failed"));
    }

    constexpr std::size_t MAC_SIZE_BYTES =
        PSA_MAC_LENGTH(PSA_KEY_TYPE_HMAC, 0, PSA_ALG_HMAC(PSA_ALG_SHA_384));
    SecureBuffer mac(MAC_SIZE_BYTES);

    std::size_t mac_length = 0;
    const psa_status_t status = psa_mac_compute(
        key_id, PSA_ALG_HMAC(PSA_ALG_SHA_384),
        message.data(), message.size(),
        mac.data(), mac.size(),
        &mac_length);

    psa_destroy_key(key_id);

    if (status != PSA_SUCCESS) {
        return std::unexpected(CryptoError("HMAC-SHA-384 generation failed"));
    }

    return mac;
}


[[nodiscard]]
inline auto hmac_sha384_verify(const SecureBuffer& key,  // NOLINT(readability-function-cognitive-complexity)
                               const SecureBuffer& message,
                               const SecureBuffer& mac)
    -> std::expected<void, CryptoError>
{
    if (psa_crypto_init() != PSA_SUCCESS) {
        return std::unexpected(CryptoError("PSA crypto init failed"));
    }

    psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attrs, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&attrs, static_cast<psa_key_bits_t>(key.size() * 8));
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(&attrs, PSA_ALG_HMAC(PSA_ALG_SHA_384));

    mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
    if (psa_import_key(&attrs, key.data(), key.size(), &key_id) != PSA_SUCCESS) {
        return std::unexpected(CryptoError("Key import failed"));
    }

    const psa_status_t status = psa_mac_verify(
        key_id, PSA_ALG_HMAC(PSA_ALG_SHA_384),
        message.data(), message.size(),
        mac.data(), mac.size());

    psa_destroy_key(key_id);

    if (status != PSA_SUCCESS) {
        return std::unexpected(CryptoError("HMAC-SHA-384 verification failed"));
    }

    return {};
}
