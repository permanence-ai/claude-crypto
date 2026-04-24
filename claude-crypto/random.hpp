/*
Copyright Permanence AI, 2026. All rights reserved.

*/

#pragma once

#include <cstddef>
#include <expected>

#include <psa/crypto.h>

#include "crypto_error.hpp"
#include "secure_buffer.hpp"


[[nodiscard]]
inline auto random_bytes(const std::size_t length) -> std::expected<SecureBuffer, CryptoError>
{
    if (psa_crypto_init() != PSA_SUCCESS) {
        return std::unexpected(CryptoError(CryptoErrorCode::InitFailed, "PSA crypto init failed"));
    }

    SecureBuffer output(length);

    if (psa_generate_random(output.data(), output.size()) != PSA_SUCCESS) {
        return std::unexpected(CryptoError(CryptoErrorCode::RandomGenerationFailed, "Random byte generation failed"));
    }

    return output;
}


template<std::size_t N>
[[nodiscard]]
auto random_bytes() -> std::expected<FixedSecureBuffer<N>, CryptoError>
{
    if (psa_crypto_init() != PSA_SUCCESS) {
        return std::unexpected(CryptoError(CryptoErrorCode::InitFailed, "PSA crypto init failed"));
    }

    FixedSecureBuffer<N> output;

    if (psa_generate_random(output.data(), output.size()) != PSA_SUCCESS) {
        return std::unexpected(CryptoError(CryptoErrorCode::RandomGenerationFailed, "Random byte generation failed"));
    }

    return output;
}
