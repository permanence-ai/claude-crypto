/*
Copyright Permanence AI, 2026. All rights reserved.

*/

#include "claude_crypto.hpp"
#include "secure_buffer.hpp"

#include <mbedtls/md.h>

#include <cstddef>
#include <stdexcept>


auto sha384(const SecureBuffer& input) -> SecureBuffer {
    constexpr std::size_t SHA384_SIZE = 48;

    SecureBuffer digest(SHA384_SIZE);

    const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA384);

    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);

    if (mbedtls_md_setup(&ctx, info, 0) != 0 ||
        mbedtls_md_starts(&ctx) != 0 ||
        mbedtls_md_update(&ctx, input.data(), input.size()) != 0 ||
        mbedtls_md_finish(&ctx, digest.data()) != 0) {
        mbedtls_md_free(&ctx);
        throw std::runtime_error("SHA-384 computation failed");
    }

    mbedtls_md_free(&ctx);
    return digest;
}
