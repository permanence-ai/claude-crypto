/*
Copyright Permanence AI, 2026. All rights reserved.

*/

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

    auto raw_key_id = Provider::null_key_id();
    if (Provider::generate_key(&attrs, &raw_key_id) != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyGenerationFailed,
            "ECDH key generation failed"));
    }
    const PsaKeyHandle<Provider> key_handle(raw_key_id);

    SecureBuffer private_key_der(Provider::ec_private_key_export_size(key_bits));
    std::size_t  private_key_length = 0;

    if (Provider::export_key(key_handle.get(),
                        private_key_der.data(),
                        private_key_der.size(),
                        &private_key_length) != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyExportFailed,
            "ECDH private key export failed"));
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
            "ECDH public key export failed"));
    }
    public_key_der.resize(public_key_length);

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

    auto raw_key_id = Provider::null_key_id();
    if (Provider::import_key(&attrs,
                        our_key_pair.private_key_der.data(),
                        our_key_pair.private_key_der.size(),
                        &raw_key_id) != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyImportFailed,
            "ECDH private key import failed"));
    }
    const PsaKeyHandle<Provider> key_handle(raw_key_id);

    SecureBuffer shared_secret(Provider::ecdh_shared_secret_size(key_bits));
    std::size_t  shared_secret_length = 0;

    const auto status = Provider::raw_key_agreement(
        Provider::alg_ecdh(),
        key_handle.get(),
        peer_public_key_der.data(), peer_public_key_der.size(),
        shared_secret.data(), shared_secret.size(),
        &shared_secret_length);

    if (status != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyAgreementFailed,
            "ECDH key agreement failed"));
    }

    shared_secret.resize(shared_secret_length);
    return shared_secret;
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
