// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>
#include <string>


enum class CryptoErrorCode : std::uint8_t {
    InternalError,
    InitFailed,
    InvalidArgument,
    RandomGenerationFailed,
    KeyImportFailed,
    KeyExportFailed,
    KeyGenerationFailed,
    EncryptionFailed,
    DecryptionFailed,
    SigningFailed,
    VerificationFailed,
    MacGenerationFailed,
    DigestFailed,
    KdfSetupFailed,
    KdfInputFailed,
    KdfOutputFailed,
    KeyAgreementFailed,
    SigmaAuthFailed,
    EncapsulationFailed,
    DecapsulationFailed,
};


class CryptoError {
public:
    explicit CryptoError(const CryptoErrorCode code, std::string message)
        : code_(code), message_(std::move(message)) {}

    [[nodiscard]]
    auto code() const -> CryptoErrorCode {
        return code_;
    }

    [[nodiscard]]
    auto message() const -> const std::string& {
        return message_;
    }

private:
    CryptoErrorCode code_;
    std::string     message_;
};
