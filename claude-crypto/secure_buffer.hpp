/*
Copyright Permanence AI, 2026. All rights reserved.

*/

#pragma once

#include <mbedtls/platform_util.h>

#include <cstdint>
#include <vector>


class SecureBuffer {
public:
    explicit SecureBuffer(std::size_t size) : data_(size) {}

    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;

    SecureBuffer(SecureBuffer&&) = default;
    SecureBuffer& operator=(SecureBuffer&&) = default;

    ~SecureBuffer() {
        mbedtls_platform_zeroize(data_.data(), data_.size());
    }

    std::uint8_t* data() { return data_.data(); }
    const std::uint8_t* data() const { return data_.data(); }
    std::size_t size() const { return data_.size(); }

private:
    std::vector<std::uint8_t> data_;
};
