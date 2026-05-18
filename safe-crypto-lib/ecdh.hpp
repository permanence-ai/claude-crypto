// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstddef>
#include <expected>

#include "crypto_error.hpp"
#include "defs.hpp"
#include "ecc.hpp"
#include "psa_backend.hpp"
#include "secure_buffer.hpp"


constexpr std::size_t ecdh_p256_shared_secret_bytes = 32;
constexpr std::size_t ecdh_p384_shared_secret_bytes = 48;
constexpr std::size_t ecdh_p521_shared_secret_bytes = 66;


template<CryptoProvider Provider = DefaultProvider>
[[nodiscard]]
auto ecdh_generate_key_impl(  // NOLINT(readability-function-cognitive-complexity)
    const EcCurve curve)
    -> std::expected<EccKeyPair, CryptoError>
{
    if (Provider::crypto_init() != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InitFailed,
            "PSA crypto init failed"));
    }

    const auto key_bits = ec_curve_key_bits(curve);

    auto attrs = Provider::make_ecdh_generate_attrs(key_bits);

    auto key_result = Provider::generate_key(&attrs);
    if (!key_result.has_value()) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyGenerationFailed,
            "ECDH key generation failed"));
    }
    const PsaKeyHandle<Provider> key_handle(key_result.value());

    auto priv_result = Provider::export_key(key_handle.get());
    if (!priv_result.has_value()) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyExportFailed,
            "ECDH private key export failed"));
    }
    SecureBuffer private_key_der = std::move(priv_result).value();

    auto pub_result = Provider::export_public_key(key_handle.get());
    if (!pub_result.has_value()) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyExportFailed,
            "ECDH public key export failed"));
    }
    SecureBuffer public_key_der = std::move(pub_result).value();

    return EccKeyPair{
        .private_key_der = std::move(private_key_der),
        .public_key_der  = std::move(public_key_der),
    };
}


template<CryptoProvider Provider = DefaultProvider, SecureBufferLike PeerPublicKey>
[[nodiscard]]
auto ecdh_compute_shared_secret_impl(  // NOLINT(readability-function-cognitive-complexity)
    const EccKeyPair& our_key_pair,
    const EcCurve     curve,
    const PeerPublicKey& peer_public_key_der)
    -> std::expected<SecureBuffer, CryptoError>
{
    if (Provider::crypto_init() != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InitFailed,
            "PSA crypto init failed"));
    }

    const auto key_bits = ec_curve_key_bits(curve);

    auto attrs = Provider::make_ecdh_agree_attrs(key_bits);

    auto key_result = Provider::import_key(&attrs,
                        CByteVSpan{our_key_pair.private_key_der.data(),
                                   our_key_pair.private_key_der.size()});
    if (!key_result.has_value()) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyImportFailed,
            "ECDH private key import failed"));
    }
    const PsaKeyHandle<Provider> key_handle(key_result.value());

    auto ss_result = Provider::raw_key_agreement(
        Provider::alg_ecdh(),
        key_handle.get(),
        CByteVSpan{peer_public_key_der.data(), peer_public_key_der.size()});

    if (!ss_result.has_value()) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyAgreementFailed,
            "ECDH key agreement failed"));
    }

    return std::move(ss_result).value();
}


[[nodiscard]]
inline auto ecdh_generate_key(const EcCurve curve)
    -> std::expected<EccKeyPair, CryptoError>
{
    return ecdh_generate_key_impl(curve);
}

template<SecureBufferLike PeerPublicKey>
[[nodiscard]]
auto ecdh_compute_shared_secret(
    const EccKeyPair& our_key_pair,
    const EcCurve     curve,
    const PeerPublicKey& peer_public_key_der)
    -> std::expected<SecureBuffer, CryptoError>
{
    return ecdh_compute_shared_secret_impl<DefaultProvider>(
        our_key_pair, curve, peer_public_key_der);
}
