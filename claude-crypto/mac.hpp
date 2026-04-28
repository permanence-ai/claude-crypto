/*
Copyright Permanence AI, 2026. All rights reserved.

*/

#pragma once

#include <cstddef>
#include <expected>

#include <psa/crypto_values.h>

#include "crypto_error.hpp"
#include "defs.hpp"
#include "digests.hpp"
#include "psa_backend.hpp"
#include "secure_buffer.hpp"


template<ShaVariant V, CryptoProvider Provider = RealPsaBackend,
         SecureBufferLike Key, SecureBufferLike Message>
[[nodiscard]]
auto hmac_generate_impl(  // NOLINT(readability-function-cognitive-complexity)
    const Key& key,
    const Message& message)
    -> std::expected<FixedSecureBuffer<sha_output_size(V)>, CryptoError>
{
    constexpr psa_algorithm_t alg = PSA_ALG_HMAC(detail::sha_psa_alg(V));

    if (Provider::crypto_init() != PSA_SUCCESS) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InitFailed,
            "PSA crypto init failed"));
    }

    psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attrs, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&attrs, static_cast<psa_key_bits_t>(key.size() * bits_per_byte));
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attrs, alg);

    mbedtls_svc_key_id_t raw_key_id = MBEDTLS_SVC_KEY_ID_INIT;
    if (Provider::import_key(&attrs, key.data(), key.size(), &raw_key_id) != PSA_SUCCESS) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyImportFailed,
            "Key import failed"));
    }
    const PsaKeyHandle<Provider> key_handle(raw_key_id);

    FixedSecureBuffer<sha_output_size(V)> mac;
    std::size_t mac_length = 0;

    const psa_status_t status = Provider::mac_compute(
        key_handle.get(), alg,
        message.data(), message.size(),
        mac.data(), mac.size(),
        &mac_length);

    if (status != PSA_SUCCESS) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::MacGenerationFailed,
            "HMAC generation failed"));
    }

    return mac;
}


template<ShaVariant V, CryptoProvider Provider = RealPsaBackend,
         SecureBufferLike Key, SecureBufferLike Message>
[[nodiscard]]
auto hmac_verify_impl(  // NOLINT(readability-function-cognitive-complexity)
    const Key& key,
    const Message& message,
    const FixedSecureBuffer<sha_output_size(V)>& mac)
    -> std::expected<bool, CryptoError>
{
    constexpr psa_algorithm_t alg = PSA_ALG_HMAC(detail::sha_psa_alg(V));

    if (Provider::crypto_init() != PSA_SUCCESS) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InitFailed,
            "PSA crypto init failed"));
    }

    psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attrs, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&attrs, static_cast<psa_key_bits_t>(key.size() * bits_per_byte));
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(&attrs, alg);

    mbedtls_svc_key_id_t raw_key_id = MBEDTLS_SVC_KEY_ID_INIT;
    if (Provider::import_key(&attrs, key.data(), key.size(), &raw_key_id) != PSA_SUCCESS) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyImportFailed,
            "Key import failed"));
    }
    const PsaKeyHandle<Provider> key_handle(raw_key_id);

    const psa_status_t status = Provider::mac_verify(
        key_handle.get(), alg,
        message.data(), message.size(),
        mac.data(), mac.size());

    if (status == PSA_ERROR_INVALID_SIGNATURE) {
        return false;
    }
    if (status != PSA_SUCCESS) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::VerificationFailed,
            "HMAC verification failed"));
    }

    return true;
}


template<ShaVariant V, SecureBufferLike Key, SecureBufferLike Message>
[[nodiscard]]
auto hmac_generate(const Key& key, const Message& message)
    -> std::expected<FixedSecureBuffer<sha_output_size(V)>, CryptoError>
{
    return hmac_generate_impl<V, RealPsaBackend>(key, message);
}


template<ShaVariant V, SecureBufferLike Key, SecureBufferLike Message>
[[nodiscard]]
auto hmac_verify(
    const Key& key,
    const Message& message,
    const FixedSecureBuffer<sha_output_size(V)>& mac)
    -> std::expected<bool, CryptoError>
{
    return hmac_verify_impl<V, RealPsaBackend>(key, message, mac);
}
