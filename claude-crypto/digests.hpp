/*
Copyright Permanence AI, 2026. All rights reserved.

*/

#pragma once

#include <cstddef>
#include <expected>

#include <mbedtls/md.h>

#include "crypto_error.hpp"
#include "secure_buffer.hpp"


constexpr std::size_t SHA384_SIZE_BYTES = 48;


template<SecureBufferLike Input>
[[nodiscard]]
inline auto sha384(const Input& input)
    -> std::expected<FixedSecureBuffer<SHA384_SIZE_BYTES>, CryptoError>
{
    FixedSecureBuffer<SHA384_SIZE_BYTES> digest;

    const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA384);

    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);

    if (mbedtls_md_setup(&ctx, info, 0) != 0 ||
        mbedtls_md_starts(&ctx) != 0 ||
        mbedtls_md_update(&ctx, input.data(), input.size()) != 0 ||
        mbedtls_md_finish(&ctx, digest.data()) != 0) {
        mbedtls_md_free(&ctx);
        return std::unexpected(CryptoError("SHA-384 computation failed"));
    }

    mbedtls_md_free(&ctx);
    return digest;
}
