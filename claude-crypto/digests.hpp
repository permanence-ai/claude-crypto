/*
Copyright Permanence AI, 2026. All rights reserved.

*/

#pragma once

#include <cstddef>
#include <expected>

#include <mbedtls/md.h>

#include "crypto_error.hpp"
#include "secure_buffer.hpp"


enum class ShaVariant : std::uint8_t {
    Sha256,
    Sha384,
    Sha512,
};

constexpr std::size_t SHA256_SIZE_BYTES = 32;
constexpr std::size_t SHA384_SIZE_BYTES = 48;
constexpr std::size_t SHA512_SIZE_BYTES = 64;

consteval std::size_t sha_output_size(const ShaVariant v) {
    if (v == ShaVariant::Sha256) {
        return SHA256_SIZE_BYTES;
    }
    if (v == ShaVariant::Sha384) {
        return SHA384_SIZE_BYTES;
    }
    return SHA512_SIZE_BYTES;
}


template<ShaVariant V, SecureBufferLike Input>
[[nodiscard]]
inline auto sha(const Input& input)
    -> std::expected<FixedSecureBuffer<sha_output_size(V)>, CryptoError>
{
    constexpr mbedtls_md_type_t md_type = [] {
        if constexpr (V == ShaVariant::Sha256) {
            return MBEDTLS_MD_SHA256;
        } else if constexpr (V == ShaVariant::Sha384) {
            return MBEDTLS_MD_SHA384;
        } else {
            return MBEDTLS_MD_SHA512;
        }
    }();

    FixedSecureBuffer<sha_output_size(V)> digest;

    const mbedtls_md_info_t* info = mbedtls_md_info_from_type(md_type);

    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);

    if (mbedtls_md_setup(&ctx, info, 0) != 0 ||
        mbedtls_md_starts(&ctx) != 0 ||
        mbedtls_md_update(&ctx, input.data(), input.size()) != 0 ||
        mbedtls_md_finish(&ctx, digest.data()) != 0) {
        mbedtls_md_free(&ctx);
        return std::unexpected(CryptoError("SHA computation failed"));
    }

    mbedtls_md_free(&ctx);
    return digest;
}
