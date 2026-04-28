/*
Copyright Permanence AI, 2026. All rights reserved.

*/

#pragma once

#include <cstddef>
#include <expected>

#include "crypto_error.hpp"
#include "psa_backend.hpp"
#include "secure_buffer.hpp"
#include "sha_variant.hpp"


template<ShaVariant V, CryptoProvider Provider = RealPsaBackend, SecureBufferLike Input>
[[nodiscard]]
auto sha_impl(const Input& input)
    -> std::expected<FixedSecureBuffer<sha_output_size(V)>, CryptoError>
{
    if (Provider::crypto_init() != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InitFailed,
            "PSA crypto init failed"));
    }

    FixedSecureBuffer<sha_output_size(V)> digest;
    std::size_t digest_length = 0;

    const auto status = Provider::hash_compute(
        Provider::alg_sha(V),
        input.data(), input.size(),
        digest.data(), digest.size(),
        &digest_length);

    if (status != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::DigestFailed,
            "SHA computation failed"));
    }

    return digest;
}


template<ShaVariant V, SecureBufferLike Input>
[[nodiscard]]
auto sha(const Input& input)
    -> std::expected<FixedSecureBuffer<sha_output_size(V)>, CryptoError>
{
    return sha_impl<V, RealPsaBackend>(input);
}
