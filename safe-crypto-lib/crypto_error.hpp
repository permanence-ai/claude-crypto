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
    // noexcept overload — safe in noexcept contexts; stores a string literal pointer.
    explicit CryptoError(const CryptoErrorCode code, const char* message) noexcept
        : code_(code), literal_(message) {}

    // Owning overload — for dynamic messages; may throw on allocation failure.
    explicit CryptoError(const CryptoErrorCode code, std::string message)
        : code_(code), owned_(std::move(message)), literal_(nullptr) {}

    [[nodiscard]]
    auto code() const noexcept -> CryptoErrorCode {
        return code_;
    }

    // Returns the message as a std::string.  May allocate when constructed
    // via the const char* overload; only call from non-critical paths.
    [[nodiscard]]
    auto message() const -> std::string {
        return literal_ != nullptr ? std::string{literal_} : owned_;
    }

private:
    CryptoErrorCode code_;
    std::string     owned_;
    const char*     literal_;
};
