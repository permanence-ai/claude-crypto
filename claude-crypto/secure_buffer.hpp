/*
Copyright Permanence AI, 2026. All rights reserved.

*/

#pragma once

#include <mbedtls/platform_util.h>

#include <array>
#include <concepts>
#include <cstddef>
#include <vector>

#include "defs.hpp"


template<typename T>
concept SecureBufferLike = requires(const T& t) {
    { t.data() } -> std::same_as<const CRYPTO_BYTE*>;
    { t.size() } -> std::convertible_to<std::size_t>;
};


// Dynamic (heap-allocated) secure buffer — zeroised on destruction.
class SecureBuffer {
public:
    explicit SecureBuffer(const std::size_t size) : data_(size) {}

    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;

    SecureBuffer(SecureBuffer&&) = default;
    SecureBuffer& operator=(SecureBuffer&&) = default;

    ~SecureBuffer() {
        mbedtls_platform_zeroize(data_.data(), data_.size());
    }

    [[nodiscard]]
    auto data() -> CRYPTO_BYTE* {
        return data_.data();
    }

    [[nodiscard]]
    auto data() const -> const CRYPTO_BYTE* {
        return data_.data();
    }

    [[nodiscard]]
    auto size() const -> std::size_t {
        return data_.size();
    }

    [[nodiscard]]
    auto empty() const -> bool {
        return data_.empty();
    }

    auto resize(const std::size_t new_size) -> void {
        if (new_size < data_.size()) {
            mbedtls_platform_zeroize(data_.data() + new_size, data_.size() - new_size);
        }
        data_.resize(new_size);
    }

    [[nodiscard]]
    auto begin() -> std::vector<CRYPTO_BYTE>::iterator {
        return data_.begin();
    }

    [[nodiscard]]
    auto begin() const -> std::vector<CRYPTO_BYTE>::const_iterator {
        return data_.begin();
    }

    [[nodiscard]]
    auto end() -> std::vector<CRYPTO_BYTE>::iterator {
        return data_.end();
    }

    [[nodiscard]]
    auto end() const -> std::vector<CRYPTO_BYTE>::const_iterator {
        return data_.end();
    }

    [[nodiscard]]
    auto operator[](const std::size_t i) -> CRYPTO_BYTE& {
        return data_.at(i);
    }

    [[nodiscard]]
    auto operator[](const std::size_t i) const -> const CRYPTO_BYTE& {
        return data_.at(i);
    }

private:
    std::vector<CRYPTO_BYTE> data_;
};


// Fixed-size (stack-allocated) secure buffer — zero-initialised on construction,
// zeroised on destruction.
template<std::size_t N>
class FixedSecureBuffer {
public:
    FixedSecureBuffer() = default;

    FixedSecureBuffer(const FixedSecureBuffer&) = delete;
    FixedSecureBuffer& operator=(const FixedSecureBuffer&) = delete;

    FixedSecureBuffer(FixedSecureBuffer&&) = default;
    FixedSecureBuffer& operator=(FixedSecureBuffer&&) = default;

    ~FixedSecureBuffer() {
        mbedtls_platform_zeroize(data_.data(), data_.size());
    }

    [[nodiscard]]
    auto data() -> CRYPTO_BYTE* {
        return data_.data();
    }

    [[nodiscard]]
    auto data() const -> const CRYPTO_BYTE* {
        return data_.data();
    }

    [[nodiscard]]
    constexpr auto size() const -> std::size_t {
        return N;
    }

    [[nodiscard]]
    constexpr auto empty() const -> bool {
        return N == 0;
    }

    [[nodiscard]]
    auto begin() -> typename std::array<CRYPTO_BYTE, N>::iterator {
        return data_.begin();
    }

    [[nodiscard]]
    auto begin() const -> typename std::array<CRYPTO_BYTE, N>::const_iterator {
        return data_.begin();
    }

    [[nodiscard]]
    auto end() -> typename std::array<CRYPTO_BYTE, N>::iterator {
        return data_.end();
    }

    [[nodiscard]]
    auto end() const -> typename std::array<CRYPTO_BYTE, N>::const_iterator {
        return data_.end();
    }

    [[nodiscard]]
    auto operator[](const std::size_t i) -> CRYPTO_BYTE& {
        return data_.at(i);
    }

    [[nodiscard]]
    auto operator[](const std::size_t i) const -> const CRYPTO_BYTE& {
        return data_.at(i);
    }

private:
    std::array<CRYPTO_BYTE, N> data_{};
};
