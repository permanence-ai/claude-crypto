/*
Copyright Permanence AI, 2026. All rights reserved.

*/

#pragma once

#include <cstddef>
#include <expected>

#include "contracts.hpp"
#include "crypto_error.hpp"
#include "psa_backend.hpp"
#include "secure_buffer.hpp"


template<CryptoProvider Provider = RealPsaBackend>
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

    SecureBuffer output(length);

    if (Provider::generate_random(output.data(), output.size()) != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::RandomGenerationFailed,
            "Random byte generation failed"));
    }

    return output;
}


template<std::size_t N, CryptoProvider Provider = RealPsaBackend>
[[nodiscard]]
auto random_bytes_fixed_impl() -> std::expected<FixedSecureBuffer<N>, CryptoError>
{
    if (Provider::crypto_init() != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InitFailed,
            "PSA crypto init failed"));
    }

    FixedSecureBuffer<N> output;

    if (Provider::generate_random(output.data(), output.size()) != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::RandomGenerationFailed,
            "Random byte generation failed"));
    }

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
