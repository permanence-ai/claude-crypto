/*
Copyright Permanence AI, 2026. All rights reserved.

*/

#pragma once

#include <cstddef>
#include <expected>

#include <psa/crypto.h>
#include <psa/crypto_sizes.h>
#include <psa/crypto_values.h>

#include "crypto_error.hpp"
#include "defs.hpp"
#include "ecc.hpp"
#include "psa_backend.hpp"
#include "secure_buffer.hpp"


constexpr std::size_t ecdh_p256_shared_secret_bytes = 32;
constexpr std::size_t ecdh_p384_shared_secret_bytes = 48;
constexpr std::size_t ecdh_p521_shared_secret_bytes = 66;


template<CryptoProvider Provider = RealPsaBackend>
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

    const psa_ecc_family_t family   = PSA_ECC_FAMILY_SECP_R1;
    const auto key_bits = static_cast<psa_key_bits_t>(ec_curve_key_bits(curve));

    auto attrs = Provider::make_key_attrs();
    psa_set_key_type(&attrs, PSA_KEY_TYPE_ECC_KEY_PAIR(family));
    psa_set_key_bits(&attrs, key_bits);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attrs, PSA_ALG_ECDH);

    auto raw_key_id = Provider::null_key_id();
    if (Provider::generate_key(&attrs, &raw_key_id) != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyGenerationFailed,
            "ECDH key generation failed"));
    }
    const PsaKeyHandle<Provider> key_handle(raw_key_id);

    const std::size_t private_key_size =
        PSA_EXPORT_KEY_OUTPUT_SIZE(PSA_KEY_TYPE_ECC_KEY_PAIR(family), key_bits);
    SecureBuffer private_key_der(private_key_size);
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

    const std::size_t public_key_size =
        PSA_EXPORT_PUBLIC_KEY_OUTPUT_SIZE(PSA_KEY_TYPE_ECC_KEY_PAIR(family), key_bits);
    SecureBuffer public_key_der(public_key_size);
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


template<CryptoProvider Provider = RealPsaBackend, SecureBufferLike PeerPublicKey>
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

    const psa_ecc_family_t family   = PSA_ECC_FAMILY_SECP_R1;
    const auto key_bits = static_cast<psa_key_bits_t>(ec_curve_key_bits(curve));

    auto attrs = Provider::make_key_attrs();
    psa_set_key_type(&attrs, PSA_KEY_TYPE_ECC_KEY_PAIR(family));
    psa_set_key_bits(&attrs, key_bits);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attrs, PSA_ALG_ECDH);

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

    const std::size_t shared_secret_size =
        PSA_RAW_KEY_AGREEMENT_OUTPUT_SIZE(PSA_KEY_TYPE_ECC_KEY_PAIR(family), key_bits);
    SecureBuffer shared_secret(shared_secret_size);
    std::size_t  shared_secret_length = 0;

    const auto status = Provider::raw_key_agreement(
        PSA_ALG_ECDH,
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
    return ecdh_compute_shared_secret_impl<RealPsaBackend>(
        our_key_pair, curve, peer_public_key_der);
}
