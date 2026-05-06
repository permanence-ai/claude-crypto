// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstddef>
#include <cstdint>
#include <random>
#include <span>

#include "secure_buffer.hpp"


// Test-only: uses std::mt19937 which is not cryptographically secure.
[[nodiscard]]
inline auto make_random_secure_buffer(const std::size_t size) -> SecureBuffer {
    constexpr unsigned int MAX_BYTE = 255;
    SecureBuffer buf(size);

    std::random_device rd;
    std::seed_seq seed{rd()};
    std::mt19937 rng(seed);
    std::uniform_int_distribution<unsigned int> dist(0, MAX_BYTE);

    for (auto& byte : std::span(buf.data(), buf.size())) {
        byte = static_cast<CryptoByte>(dist(rng));
    }

    return buf;
}


// Test-only: uses std::mt19937 which is not cryptographically secure.
template<std::size_t N>
[[nodiscard]]
auto make_random_fixed_secure_buffer() -> FixedSecureBuffer<N> {
    constexpr unsigned int MAX_BYTE = 255;
    FixedSecureBuffer<N> buf;

    std::random_device rd;
    std::seed_seq seed{rd()};
    std::mt19937 rng(seed);
    std::uniform_int_distribution<unsigned int> dist(0, MAX_BYTE);

    for (auto& byte : std::span(buf.data(), buf.size())) {
        byte = static_cast<CryptoByte>(dist(rng));
    }

    return buf;
}
