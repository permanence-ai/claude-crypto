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
    auto begin() -> std::vector<std::uint8_t>::iterator {
        return data_.begin();
    }

    [[nodiscard]]
    auto begin() const -> std::vector<std::uint8_t>::const_iterator {
        return data_.begin();
    }

    [[nodiscard]]
    auto end() -> std::vector<std::uint8_t>::iterator {
        return data_.end();
    }

    [[nodiscard]]
    auto end() const -> std::vector<std::uint8_t>::const_iterator {
        return data_.end();
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
