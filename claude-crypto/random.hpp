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
        return std::unexpected(CryptoError("PSA crypto init failed"));
    }

    SecureBuffer output(length);

    if (psa_generate_random(output.data(), output.size()) != PSA_SUCCESS) {
        return std::unexpected(CryptoError("Random byte generation failed"));
    }

    return output;
}
