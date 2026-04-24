/*
Copyright Permanence AI, 2026. All rights reserved.

*/

#pragma once

#include <string>


class CryptoError {
public:
    explicit CryptoError(std::string message) : message_(std::move(message)) {}

    [[nodiscard]]
    auto message() const -> const std::string& {
        return message_;
    }

private:
    std::string message_;
};
