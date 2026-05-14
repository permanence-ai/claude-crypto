// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>

#include "crypto_error.hpp"
#include "defs.hpp"
#include "psa_backend.hpp"
#include "secure_buffer.hpp"


enum class EcCurve : std::uint8_t {
    P256,
    P384,
    P521,
};

constexpr std::size_t p256_key_bits = 256;
constexpr std::size_t p384_key_bits = 384;
constexpr std::size_t p521_key_bits = 521;

[[nodiscard]]
constexpr auto ec_curve_key_bits(const EcCurve curve) -> std::size_t {
    switch (curve) {
        case EcCurve::P256: return p256_key_bits;
        case EcCurve::P384: return p384_key_bits;
        case EcCurve::P521: return p521_key_bits;
    }
}

struct EcPublicKey {
    SecureBuffer public_key_der;
};

struct EccKeyPair {
    SecureBuffer private_key_der;
    SecureBuffer public_key_der;
};


template<CryptoProvider Provider = DefaultProvider>
[[nodiscard]]
auto ecdsa_generate_key_impl(  // NOLINT(readability-function-cognitive-complexity)
    const EcCurve curve)
    -> std::expected<EccKeyPair, CryptoError>
{
    if (Provider::crypto_init() != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InitFailed,
            "PSA crypto init failed"));
    }

    const auto key_bits = ec_curve_key_bits(curve);

    auto attrs = Provider::make_ecdsa_generate_attrs(key_bits);

    auto key_result = Provider::generate_key(&attrs);
    if (!key_result.has_value()) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyGenerationFailed,
            "ECDSA key generation failed"));
    }
    const PsaKeyHandle<Provider> key_handle(key_result.value());

    SecureBuffer private_key_der(Provider::ec_private_key_export_size(key_bits));
    std::size_t  private_key_length = 0;

    if (Provider::export_key(key_handle.get(),
                        private_key_der.data(),
                        private_key_der.size(),
                        &private_key_length) != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyExportFailed,
            "ECDSA private key export failed"));
    }
    private_key_der.resize(private_key_length);

    SecureBuffer public_key_der(Provider::ec_public_key_export_size(key_bits));
    std::size_t  public_key_length = 0;

    if (Provider::export_public_key(key_handle.get(),
                               public_key_der.data(),
                               public_key_der.size(),
                               &public_key_length) != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyExportFailed,
            "ECDSA public key export failed"));
    }
    public_key_der.resize(public_key_length);

    return EccKeyPair{
        .private_key_der = std::move(private_key_der),
        .public_key_der  = std::move(public_key_der),
    };
}


template<CryptoProvider Provider = DefaultProvider, SecureBufferLike Message>
[[nodiscard]]
auto ecdsa_sign_impl(  // NOLINT(readability-function-cognitive-complexity)
    const EccKeyPair& key_pair,
    const EcCurve curve,
    const Message& message)
    -> std::expected<SecureBuffer, CryptoError>
{
    if (Provider::crypto_init() != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InitFailed,
            "PSA crypto init failed"));
    }

    const auto key_bits = ec_curve_key_bits(curve);

    auto attrs = Provider::make_ecdsa_sign_attrs(key_bits);

    auto key_result = Provider::import_key(&attrs,
                        key_pair.private_key_der.data(),
                        key_pair.private_key_der.size());
    if (!key_result.has_value()) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyImportFailed,
            "ECDSA private key import failed"));
    }
    const PsaKeyHandle<Provider> key_handle(key_result.value());

    SecureBuffer signature(Provider::ecdsa_sign_output_size(key_bits));
    std::size_t  signature_length = 0;

    const auto status = Provider::sign_message(
        key_handle.get(),
        Provider::alg_ecdsa(),
        message.data(), message.size(),
        signature.data(), signature.size(),
        &signature_length);

    if (status != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::SigningFailed,
            "ECDSA signing failed"));
    }

    signature.resize(signature_length);
    return signature;
}


template<CryptoProvider Provider = DefaultProvider,
         SecureBufferLike Message, SecureBufferLike Signature>
[[nodiscard]]
auto ecdsa_verify_impl(  // NOLINT(readability-function-cognitive-complexity)
    const EcPublicKey& public_key,
    const EcCurve curve,
    const Message& message,
    const Signature& signature)
    -> std::expected<bool, CryptoError>
{
    if (Provider::crypto_init() != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InitFailed,
            "PSA crypto init failed"));
    }

    const auto key_bits = ec_curve_key_bits(curve);

    auto attrs = Provider::make_ecdsa_verify_attrs(key_bits);

    auto key_result = Provider::import_key(&attrs,
                        public_key.public_key_der.data(),
                        public_key.public_key_der.size());
    if (!key_result.has_value()) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyImportFailed,
            "ECDSA public key import failed"));
    }
    const PsaKeyHandle<Provider> key_handle(key_result.value());

    const auto status = Provider::verify_message(
        key_handle.get(),
        Provider::alg_ecdsa(),
        message.data(), message.size(),
        signature.data(), signature.size());

    if (status == Provider::err_invalid_sig || status == Provider::err_invalid_arg) {
        return false;
    }
    if (status != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::VerificationFailed,
            "ECDSA verification failed"));
    }

    return true;
}


[[nodiscard]]
inline auto ecdsa_generate_key(const EcCurve curve)
    -> std::expected<EccKeyPair, CryptoError>
{
    return ecdsa_generate_key_impl(curve);
}

template<SecureBufferLike Message>
[[nodiscard]]
auto ecdsa_sign(
    const EccKeyPair& key_pair,
    const EcCurve curve,
    const Message& message)
    -> std::expected<SecureBuffer, CryptoError>
{
    return ecdsa_sign_impl<DefaultProvider>(key_pair, curve, message);
}

template<SecureBufferLike Message, SecureBufferLike Signature>
[[nodiscard]]
auto ecdsa_verify(
    const EcPublicKey& public_key,
    const EcCurve curve,
    const Message& message,
    const Signature& signature)
    -> std::expected<bool, CryptoError>
{
    return ecdsa_verify_impl<DefaultProvider>(public_key, curve, message, signature);
}
