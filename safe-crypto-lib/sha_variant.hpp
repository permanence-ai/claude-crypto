// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Permanence AI

#pragma once

#include <cstddef>
#include <cstdint>


// SHA algorithm selector — no external dependencies, safe to include from provider headers.
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
