// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>

#include "crypto_error.hpp"
#include "crypto_log.hpp"
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

template<EcCurve C>
struct EcPublicKey {
    static constexpr EcCurve curve = C;
    SecureBuffer public_key_der;
};

template<EcCurve C>
struct EccKeyPair {
    static constexpr EcCurve curve = C;
    SecureBuffer private_key_der;
    SecureBuffer public_key_der;
};


template<EcCurve C, CryptoProvider Provider = DefaultProvider>
[[nodiscard]]
auto ecdsa_generate_key_impl(  // NOLINT(readability-function-cognitive-complexity)
    )
    -> std::expected<EccKeyPair<C>, CryptoError>
{
    if (Provider::crypto_init() != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InitFailed,
            "PSA crypto init failed"));
    }

    const auto key_bits = ec_curve_key_bits(C);

    auto attrs = Provider::make_ecdsa_generate_attrs(key_bits);

    auto key_result = Provider::generate_key(&attrs);
    if (!key_result.has_value()) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyGenerationFailed,
            "ECDSA key generation failed"));
    }
    const PsaKeyHandle<Provider> key_handle(key_result.value());

    auto priv_result = Provider::export_key(key_handle.get());
    if (!priv_result.has_value()) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyExportFailed,
            "ECDSA private key export failed"));
    }
    SecureBuffer private_key_der = std::move(priv_result).value();

    auto pub_result = Provider::export_public_key(key_handle.get());
    if (!pub_result.has_value()) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyExportFailed,
            "ECDSA public key export failed"));
    }
    SecureBuffer public_key_der = std::move(pub_result).value();

    return EccKeyPair<C>{
        .private_key_der = std::move(private_key_der),
        .public_key_der  = std::move(public_key_der),
    };
}


template<CryptoProvider Provider = DefaultProvider, EcCurve C, SecureBufferLike Message>
[[nodiscard]]
auto ecdsa_sign_impl(  // NOLINT(readability-function-cognitive-complexity)
    const EccKeyPair<C>& key_pair,
    const Message& message)
    -> std::expected<SecureBuffer, CryptoError>
{
    if (Provider::crypto_init() != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InitFailed,
            "PSA crypto init failed"));
    }

    const auto key_bits = ec_curve_key_bits(C);

    auto attrs = Provider::make_ecdsa_sign_attrs(key_bits);

    auto key_result = Provider::import_key(&attrs,
                        CByteVSpan{key_pair.private_key_der.data(),
                                   key_pair.private_key_der.size()});
    if (!key_result.has_value()) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyImportFailed,
            "ECDSA private key import failed"));
    }
    const PsaKeyHandle<Provider> key_handle(key_result.value());

    auto sig_result = Provider::sign_message(
        key_handle.get(),
        Provider::alg_ecdsa(),
        CByteVSpan{message.data(), message.size()});

    if (!sig_result.has_value()) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::SigningFailed,
            "ECDSA signing failed"));
    }

    return std::move(sig_result).value();
}


template<CryptoProvider Provider = DefaultProvider,
         EcCurve C, SecureBufferLike Message, SecureBufferLike Signature>
[[nodiscard]]
auto ecdsa_verify_impl(  // NOLINT(readability-function-cognitive-complexity)
    const EcPublicKey<C>& public_key,
    const Message& message,
    const Signature& signature)
    -> std::expected<bool, CryptoError>
{
    if (Provider::crypto_init() != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InitFailed,
            "PSA crypto init failed"));
    }

    const auto key_bits = ec_curve_key_bits(C);

    auto attrs = Provider::make_ecdsa_verify_attrs(key_bits);

    auto key_result = Provider::import_key(&attrs,
                        CByteVSpan{public_key.public_key_der.data(),
                                   public_key.public_key_der.size()});
    if (!key_result.has_value()) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyImportFailed,
            "ECDSA public key import failed"));
    }
    const PsaKeyHandle<Provider> key_handle(key_result.value());

    const auto status = Provider::verify_message(
        key_handle.get(),
        Provider::alg_ecdsa(),
        CByteVSpan{message.data(), message.size()},
        CByteVSpan{signature.data(), signature.size()});

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


template<EcCurve C>
[[nodiscard]]
auto ecdsa_generate_key()
    -> std::expected<EccKeyPair<C>, CryptoError>
{
    if (crypto_log_enabled(CryptoLogLevel::Debug)) {
        crypto_log(CryptoLogLevel::Debug, "ecdsa_generate_key: entry");
    }
    auto result = ecdsa_generate_key_impl<C>();
    if (!result.has_value()) {
        crypto_log(CryptoLogLevel::Error, "ecdsa_generate_key: " + result.error().message());
    } else if (crypto_log_enabled(CryptoLogLevel::Debug)) {
        crypto_log(CryptoLogLevel::Debug,
            crypto_log_detail::msg("ecdsa_generate_key",
                "priv", result->private_key_der.size(),
                "pub",  result->public_key_der.size()));
    }
    return result;
}

template<EcCurve C, SecureBufferLike Message>
[[nodiscard]]
auto ecdsa_sign(
    const EccKeyPair<C>& key_pair,
    const Message& message)
    -> std::expected<SecureBuffer, CryptoError>
{
    if (crypto_log_enabled(CryptoLogLevel::Debug)) {
        crypto_log(CryptoLogLevel::Debug,
            crypto_log_detail::msg("ecdsa_sign", "msg", message.size()));
    }
    auto result = ecdsa_sign_impl<DefaultProvider>(key_pair, message);
    if (!result.has_value()) {
        crypto_log(CryptoLogLevel::Error, "ecdsa_sign: " + result.error().message());
    } else if (crypto_log_enabled(CryptoLogLevel::Debug)) {
        crypto_log(CryptoLogLevel::Debug,
            crypto_log_detail::msg("ecdsa_sign", "sig", result->size()));
    }
    return result;
}

template<EcCurve C, SecureBufferLike Message, SecureBufferLike Signature>
[[nodiscard]]
auto ecdsa_verify(
    const EcPublicKey<C>& public_key,
    const Message& message,
    const Signature& signature)
    -> std::expected<bool, CryptoError>
{
    if (crypto_log_enabled(CryptoLogLevel::Debug)) {
        crypto_log(CryptoLogLevel::Debug,
            crypto_log_detail::msg("ecdsa_verify",
                "msg", message.size(),
                "sig", signature.size()));
    }
    auto result = ecdsa_verify_impl<DefaultProvider>(public_key, message, signature);
    if (!result.has_value()) {
        crypto_log(CryptoLogLevel::Error, "ecdsa_verify: " + result.error().message());
    } else if (crypto_log_enabled(CryptoLogLevel::Debug)) {
        crypto_log(CryptoLogLevel::Debug,
            result.value() ? "ecdsa_verify: ok" : "ecdsa_verify: mismatch");
    }
    return result;
}
