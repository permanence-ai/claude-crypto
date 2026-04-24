/*
Copyright Permanence AI, 2026. All rights reserved.

*/

#pragma once

#include <cstddef>
#include <cstdint>
#include <random>
#include <span>

#include "secure_buffer.hpp"


// Test-only: uses std::mt19937 which is not cryptographically secure.
[[nodiscard]]
inline auto make_random_secure_buffer(const std::size_t size) -> SecureBuffer {
    SecureBuffer buf(size);

    std::random_device rd;
    std::seed_seq seed{rd()};
    std::mt19937 rng(seed);
    std::uniform_int_distribution<unsigned int> dist(0, 255);

    for (auto& byte : std::span(buf.data(), buf.size())) {
        byte = static_cast<CRYPTO_BYTE>(dist(rng));
    }

    return buf;
}


// Test-only: uses std::mt19937 which is not cryptographically secure.
template<std::size_t N>
[[nodiscard]]
auto make_random_fixed_secure_buffer() -> FixedSecureBuffer<N> {
    FixedSecureBuffer<N> buf;

    std::random_device rd;
    std::seed_seq seed{rd()};
    std::mt19937 rng(seed);
    std::uniform_int_distribution<unsigned int> dist(0, 255);

    for (auto& byte : std::span(buf.data(), buf.size())) {
        byte = static_cast<CRYPTO_BYTE>(dist(rng));
    }

    return buf;
}
