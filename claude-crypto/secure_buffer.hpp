/*
Copyright Permanence AI, 2026. All rights reserved.

*/

#pragma once

#include <mbedtls/platform_util.h>

#include <cstdint>
#include <vector>


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
    auto data() -> std::uint8_t* {
        return data_.data();
    }

    [[nodiscard]]
    auto data() const -> const std::uint8_t* {
        return data_.data();
    }

    [[nodiscard]]
    auto size() const -> std::size_t {
        return data_.size();
    }

    [[nodiscard]]
    auto operator[](const std::size_t i) -> std::uint8_t& {
        return data_.at(i);
    }

    [[nodiscard]]
    auto operator[](const std::size_t i) const -> const std::uint8_t& {
        return data_.at(i);
    }

private:
    std::vector<std::uint8_t> data_;
};
