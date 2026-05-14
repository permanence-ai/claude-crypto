// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstddef>
#include <cstring>
#include <expected>

#include "crypto_error.hpp"
#include "psa_backend.hpp"
#include "secure_buffer.hpp"
#include "sha_variant.hpp"


template<ShaVariant V, CryptoProvider Provider = DefaultProvider, SecureBufferLike Input>
[[nodiscard]]
auto sha_impl(const Input& input)
    -> std::expected<FixedSecureBuffer<sha_output_size(V)>, CryptoError>
{
    if (Provider::crypto_init() != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InitFailed,
            "PSA crypto init failed"));
    }

    auto result = Provider::hash_compute(
        Provider::alg_sha(V),
        input.data(), input.size());

    if (!result.has_value()) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::DigestFailed,
            "SHA computation failed"));
    }

    FixedSecureBuffer<sha_output_size(V)> digest;
    std::memcpy(digest.data(), result->data(), sha_output_size(V));
    return digest;
}


template<ShaVariant V, SecureBufferLike Input>
[[nodiscard]]
auto sha(const Input& input)
    -> std::expected<FixedSecureBuffer<sha_output_size(V)>, CryptoError>
{
    return sha_impl<V, DefaultProvider>(input);
}
