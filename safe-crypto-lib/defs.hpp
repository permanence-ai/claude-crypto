// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Permanence AI

#pragma once

#include <cstddef>
#include <cstdint>


using CryptoByte = std::uint8_t;

constexpr std::size_t bits_per_byte = 8;

constexpr std::size_t aes256_key_size_bytes  = 32;
constexpr std::size_t aes256_key_bits        = aes256_key_size_bytes  * bits_per_byte;
constexpr std::size_t chacha20_key_size_bytes = 32;
constexpr std::size_t chacha20_key_bits       = chacha20_key_size_bytes * bits_per_byte;
