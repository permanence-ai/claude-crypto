// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstddef>
#include <cstring>
#include <expected>

#include "contracts.hpp"
#include "crypto_error.hpp"
#include "psa_backend.hpp"
#include "secure_buffer.hpp"


template<CryptoProvider Provider = DefaultProvider>
[[nodiscard]]
auto random_bytes_impl(const std::size_t length)
    SAFE_CRYPTO_PRE(length > 0)
    -> std::expected<SecureBuffer, CryptoError>
{
    if (Provider::crypto_init() != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InitFailed,
            "PSA crypto init failed"));
    }

    auto result = Provider::generate_random(length);
    if (!result.has_value()) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::RandomGenerationFailed,
            "Random byte generation failed"));
    }

    return std::move(result).value();
}


template<std::size_t N, CryptoProvider Provider = DefaultProvider>
[[nodiscard]]
auto random_bytes_fixed_impl() -> std::expected<FixedSecureBuffer<N>, CryptoError>
{
    if (Provider::crypto_init() != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InitFailed,
            "PSA crypto init failed"));
    }

    auto result = Provider::generate_random(N);
    if (!result.has_value()) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::RandomGenerationFailed,
            "Random byte generation failed"));
    }

    FixedSecureBuffer<N> output;
    std::memcpy(output.data(), result->data(), N);
    return output;
}


[[nodiscard]]
inline auto random_bytes(const std::size_t length) -> std::expected<SecureBuffer, CryptoError>
{
    return random_bytes_impl(length);
}


template<std::size_t N>
[[nodiscard]]
auto random_bytes() -> std::expected<FixedSecureBuffer<N>, CryptoError>
{
    return random_bytes_fixed_impl<N>();
}
