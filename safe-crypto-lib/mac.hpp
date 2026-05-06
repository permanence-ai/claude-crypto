// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Permanence AI

#pragma once

#include <cstddef>
#include <expected>

#include "crypto_error.hpp"
#include "defs.hpp"
#include "digests.hpp"
#include "psa_backend.hpp"
#include "secure_buffer.hpp"


template<ShaVariant V, CryptoProvider Provider = DefaultProvider,
         SecureBufferLike Key, SecureBufferLike Message>
[[nodiscard]]
auto hmac_generate_impl(  // NOLINT(readability-function-cognitive-complexity)
    const Key& key,
    const Message& message)
    -> std::expected<FixedSecureBuffer<sha_output_size(V)>, CryptoError>
{
    if (Provider::crypto_init() != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InitFailed,
            "PSA crypto init failed"));
    }

    auto attrs = Provider::make_hmac_generate_attrs(V, key.size() * bits_per_byte);

    auto raw_key_id = Provider::null_key_id();
    if (Provider::import_key(&attrs, key.data(), key.size(), &raw_key_id) != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyImportFailed,
            "Key import failed"));
    }
    const PsaKeyHandle<Provider> key_handle(raw_key_id);

    FixedSecureBuffer<sha_output_size(V)> mac;
    std::size_t mac_length = 0;

    const auto status = Provider::mac_compute(
        key_handle.get(), Provider::alg_hmac(V),
        message.data(), message.size(),
        mac.data(), mac.size(),
        &mac_length);

    if (status != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::MacGenerationFailed,
            "HMAC generation failed"));
    }

    return mac;
}


template<ShaVariant V, CryptoProvider Provider = DefaultProvider,
         SecureBufferLike Key, SecureBufferLike Message>
[[nodiscard]]
auto hmac_verify_impl(  // NOLINT(readability-function-cognitive-complexity)
    const Key& key,
    const Message& message,
    const FixedSecureBuffer<sha_output_size(V)>& mac)
    -> std::expected<bool, CryptoError>
{
    if (Provider::crypto_init() != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InitFailed,
            "PSA crypto init failed"));
    }

    auto attrs = Provider::make_hmac_verify_attrs(V, key.size() * bits_per_byte);

    auto raw_key_id = Provider::null_key_id();
    if (Provider::import_key(&attrs, key.data(), key.size(), &raw_key_id) != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyImportFailed,
            "Key import failed"));
    }
    const PsaKeyHandle<Provider> key_handle(raw_key_id);

    const auto status = Provider::mac_verify(
        key_handle.get(), Provider::alg_hmac(V),
        message.data(), message.size(),
        mac.data(), mac.size());

    if (status == Provider::err_invalid_sig) {
        return false;
    }
    if (status != Provider::ok) {
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
    return hmac_generate_impl<V, DefaultProvider>(key, message);
}


template<ShaVariant V, SecureBufferLike Key, SecureBufferLike Message>
[[nodiscard]]
auto hmac_verify(
    const Key& key,
    const Message& message,
    const FixedSecureBuffer<sha_output_size(V)>& mac)
    -> std::expected<bool, CryptoError>
{
    return hmac_verify_impl<V, DefaultProvider>(key, message, mac);
}
