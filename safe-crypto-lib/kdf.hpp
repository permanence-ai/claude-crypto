// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstddef>
#include <expected>
#include <optional>
#include <string>

#include "asymmetric.hpp"
#include "contracts.hpp"
#include "crypto_error.hpp"
#include "defs.hpp"
#include "psa_backend.hpp"
#include "random.hpp"
#include "secure_buffer.hpp"


template<CryptoProvider Provider = DefaultProvider>
[[nodiscard]]
auto derive_key_impl(  // NOLINT(readability-function-cognitive-complexity)
    const std::size_t output_length, // NOLINT(bugprone-easily-swappable-parameters)
    const std::optional<SecureBuffer>& ikm  = std::nullopt, // NOLINT(bugprone-easily-swappable-parameters)
    const std::optional<SecureBuffer>& salt = std::nullopt,
    const std::optional<SecureBuffer>& info = std::nullopt)
    SAFE_CRYPTO_PRE(output_length > 0)
    -> std::expected<SecureBuffer, CryptoError>
{
    if (output_length > hkdf_sha384_max_output_bytes) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InvalidArgument,
            "output_length exceeds HKDF-SHA-384 maximum (" +
            std::to_string(hkdf_sha384_max_output_bytes) + " bytes)"));
    }

    if (ikm.has_value() && ikm->size() < output_length * 2) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InvalidArgument,
            "IKM must be at least 2 * output_length"));
    }

    if (Provider::crypto_init() != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InitFailed,
            "PSA crypto init failed"));
    }

    auto generated_ikm = std::optional<SecureBuffer>{};
    if (!ikm.has_value()) {
        auto result = random_bytes_impl<Provider>(output_length * 2);
        if (!result.has_value()) {
            return std::unexpected(result.error());
        }
        generated_ikm = std::move(*result);
    }
    const SecureBuffer& ikm_ref = ikm.has_value() ? *ikm : *generated_ikm;

    auto result = Provider::hkdf_derive(
        CByteVSpan{ikm_ref.data(), ikm_ref.size()},
        salt.has_value() ? CByteVSpan{salt->data(), salt->size()} : CByteVSpan{},
        info.has_value() ? CByteVSpan{info->data(), info->size()} : CByteVSpan{},
        output_length, false);

    if (!result.has_value()) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KdfOutputFailed,
            "HKDF derivation failed"));
    }
    return std::move(result).value();
}


template<CryptoProvider Provider = DefaultProvider>
[[nodiscard]]
auto expand_key_impl(
    const std::size_t output_length,
    const SecureBuffer& prk,
    const std::optional<SecureBuffer>& info = std::nullopt)
    SAFE_CRYPTO_PRE(output_length > 0)
    -> std::expected<SecureBuffer, CryptoError>
{
    if (output_length > hkdf_sha384_max_output_bytes) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InvalidArgument,
            "output_length exceeds HKDF-SHA-384 maximum (" +
            std::to_string(hkdf_sha384_max_output_bytes) + " bytes)"));
    }

    if (Provider::crypto_init() != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InitFailed,
            "PSA crypto init failed"));
    }

    auto result = Provider::hkdf_derive(
        CByteVSpan{prk.data(), prk.size()},
        CByteVSpan{},
        info.has_value() ? CByteVSpan{info->data(), info->size()} : CByteVSpan{},
        output_length, true);

    if (!result.has_value()) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KdfOutputFailed,
            "HKDF-Expand derivation failed"));
    }
    return std::move(result).value();
}


[[nodiscard]]
inline auto derive_key(
    const std::size_t output_length, // NOLINT(bugprone-easily-swappable-parameters)
    const std::optional<SecureBuffer>& ikm  = std::nullopt, // NOLINT(bugprone-easily-swappable-parameters)
    const std::optional<SecureBuffer>& salt = std::nullopt,
    const std::optional<SecureBuffer>& info = std::nullopt)
    -> std::expected<SecureBuffer, CryptoError>
{
    return derive_key_impl(output_length, ikm, salt, info);
}

[[nodiscard]]
inline auto expand_key(
    const std::size_t output_length,
    const SecureBuffer& prk,
    const std::optional<SecureBuffer>& info = std::nullopt)
    -> std::expected<SecureBuffer, CryptoError>
{
    return expand_key_impl(output_length, prk, info);
}


template<RsaKeyBits KB, CryptoProvider Provider = DefaultProvider>
[[nodiscard]]
auto generate_rsa_key_impl(  // NOLINT(readability-function-cognitive-complexity)
    )
    -> std::expected<RsaKeyPair<KB>, CryptoError>
{
    if (Provider::crypto_init() != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InitFailed,
            "PSA crypto init failed"));
    }

    constexpr auto key_bits_val = static_cast<std::size_t>(static_cast<std::uint16_t>(KB));

    auto attrs = Provider::make_rsa_key_pair_attrs(key_bits_val);

    auto key_result = Provider::generate_key(&attrs);
    if (!key_result.has_value()) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyGenerationFailed,
            "RSA key generation failed"));
    }
    const PsaKeyHandle<Provider> key_handle(key_result.value());

    auto priv_result = Provider::export_key(key_handle.get());
    if (!priv_result.has_value()) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyExportFailed,
            "RSA private key export failed"));
    }
    SecureBuffer private_key_der = std::move(priv_result).value();

    auto pub_result = Provider::export_public_key(key_handle.get());
    if (!pub_result.has_value()) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyExportFailed,
            "RSA public key export failed"));
    }
    SecureBuffer public_key_der = std::move(pub_result).value();

    return RsaKeyPair<KB>{
        .private_key_der = std::move(private_key_der),
        .public_key_der  = std::move(public_key_der),
    };
}


template<RsaKeyBits KB>
[[nodiscard]]
auto generate_rsa_key() -> std::expected<RsaKeyPair<KB>, CryptoError>
{
    return generate_rsa_key_impl<KB>();
}
