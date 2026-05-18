// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstddef>
#include <cstring>
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
    if (key.size() < sha_output_size(V)) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InvalidArgument,
            "HMAC key must be at least as long as the hash output"));
    }
    if (Provider::crypto_init() != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InitFailed,
            "PSA crypto init failed"));
    }

    auto attrs = Provider::make_hmac_generate_attrs(V, key.size() * bits_per_byte);

    auto key_result = Provider::import_key(&attrs, CByteVSpan{key.data(), key.size()});
    if (!key_result.has_value()) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyImportFailed,
            "Key import failed"));
    }
    const PsaKeyHandle<Provider> key_handle(key_result.value());

    auto result = Provider::mac_compute(
        key_handle.get(), Provider::alg_hmac(V),
        CByteVSpan{message.data(), message.size()});

    if (!result.has_value()) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::MacGenerationFailed,
            "HMAC generation failed"));
    }

    FixedSecureBuffer<sha_output_size(V)> mac;
    std::memcpy(mac.data(), result->data(), sha_output_size(V));
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
    if (key.size() < sha_output_size(V)) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InvalidArgument,
            "HMAC key must be at least as long as the hash output"));
    }
    if (Provider::crypto_init() != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InitFailed,
            "PSA crypto init failed"));
    }

    auto attrs = Provider::make_hmac_verify_attrs(V, key.size() * bits_per_byte);

    auto key_result = Provider::import_key(&attrs, CByteVSpan{key.data(), key.size()});
    if (!key_result.has_value()) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyImportFailed,
            "Key import failed"));
    }
    const PsaKeyHandle<Provider> key_handle(key_result.value());

    const auto status = Provider::mac_verify(
        key_handle.get(), Provider::alg_hmac(V),
        CByteVSpan{message.data(), message.size()},
        CByteVSpan{mac.data(), mac.size()});

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
