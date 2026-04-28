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

constexpr std::size_t sha256_size_bytes   = 32;
constexpr std::size_t sha384_size_bytes   = 48;
constexpr std::size_t sha512_size_bytes   = 64;
constexpr std::size_t sha3_256_size_bytes = 32;
constexpr std::size_t sha3_384_size_bytes = 48;
constexpr std::size_t sha3_512_size_bytes = 64;

consteval std::size_t sha_output_size(const ShaVariant v) {
    if (v == ShaVariant::Sha256)   { return sha256_size_bytes;   }
    if (v == ShaVariant::Sha384)   { return sha384_size_bytes;   }
    if (v == ShaVariant::Sha512)   { return sha512_size_bytes;   }
    if (v == ShaVariant::Sha3_256) { return sha3_256_size_bytes; }
    if (v == ShaVariant::Sha3_384) { return sha3_384_size_bytes; }
    return sha3_512_size_bytes;
}

namespace detail {
consteval psa_algorithm_t sha_psa_alg(const ShaVariant v) {
    if (v == ShaVariant::Sha256)   { return PSA_ALG_SHA_256;   }
    if (v == ShaVariant::Sha384)   { return PSA_ALG_SHA_384;   }
    if (v == ShaVariant::Sha512)   { return PSA_ALG_SHA_512;   }
    if (v == ShaVariant::Sha3_256) { return PSA_ALG_SHA3_256;  }
    if (v == ShaVariant::Sha3_384) { return PSA_ALG_SHA3_384;  }
    return PSA_ALG_SHA3_512;
}
}  // namespace detail


template<ShaVariant V, CryptoProvider Provider = RealPsaBackend, SecureBufferLike Input>
[[nodiscard]]
auto sha_impl(const Input& input)
    -> std::expected<FixedSecureBuffer<sha_output_size(V)>, CryptoError>
{
    if (Provider::crypto_init() != PSA_SUCCESS) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InitFailed,
            "PSA crypto init failed"));
    }

    FixedSecureBuffer<sha_output_size(V)> digest;
    std::size_t digest_length = 0;

    const psa_status_t status = Provider::hash_compute(
        detail::sha_psa_alg(V),
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
