/*
Copyright Permanence AI, 2026. All rights reserved.

*/

#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>

#include <psa/crypto_values.h>

#include "crypto_error.hpp"
#include "psa_backend.hpp"
#include "secure_buffer.hpp"


enum class ShaVariant : std::uint8_t {
    Sha256,
    Sha384,
    Sha512,
    Sha3_256,
    Sha3_384,
    Sha3_512,
};

constexpr std::size_t SHA256_SIZE_BYTES   = 32;
constexpr std::size_t SHA384_SIZE_BYTES   = 48;
constexpr std::size_t SHA512_SIZE_BYTES   = 64;
constexpr std::size_t SHA3_256_SIZE_BYTES = 32;
constexpr std::size_t SHA3_384_SIZE_BYTES = 48;
constexpr std::size_t SHA3_512_SIZE_BYTES = 64;

consteval std::size_t sha_output_size(const ShaVariant v) {
    if (v == ShaVariant::Sha256)   { return SHA256_SIZE_BYTES;   }
    if (v == ShaVariant::Sha384)   { return SHA384_SIZE_BYTES;   }
    if (v == ShaVariant::Sha512)   { return SHA512_SIZE_BYTES;   }
    if (v == ShaVariant::Sha3_256) { return SHA3_256_SIZE_BYTES; }
    if (v == ShaVariant::Sha3_384) { return SHA3_384_SIZE_BYTES; }
    return SHA3_512_SIZE_BYTES;
}

consteval psa_algorithm_t sha_psa_alg(const ShaVariant v) {
    if (v == ShaVariant::Sha256)   { return PSA_ALG_SHA_256;   }
    if (v == ShaVariant::Sha384)   { return PSA_ALG_SHA_384;   }
    if (v == ShaVariant::Sha512)   { return PSA_ALG_SHA_512;   }
    if (v == ShaVariant::Sha3_256) { return PSA_ALG_SHA3_256;  }
    if (v == ShaVariant::Sha3_384) { return PSA_ALG_SHA3_384;  }
    return PSA_ALG_SHA3_512;
}


template<ShaVariant V, typename PSA = RealPsaBackend, SecureBufferLike Input>
[[nodiscard]]
auto sha_impl(const Input& input)
    -> std::expected<FixedSecureBuffer<sha_output_size(V)>, CryptoError>
{
    if (PSA::crypto_init() != PSA_SUCCESS) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InitFailed,
            "PSA crypto init failed"));
    }

    FixedSecureBuffer<sha_output_size(V)> digest;
    std::size_t digest_length = 0;

    const psa_status_t status = PSA::hash_compute(
        sha_psa_alg(V),
        input.data(), input.size(),
        digest.data(), digest.size(),
        &digest_length);

    if (status != PSA_SUCCESS) {
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
