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
#include "secure_buffer.hpp"


constexpr psa_key_bits_t ECDH_P256_SHARED_SECRET_BYTES = 32;
constexpr psa_key_bits_t ECDH_P384_SHARED_SECRET_BYTES = 48;
constexpr psa_key_bits_t ECDH_P521_SHARED_SECRET_BYTES = 66;


[[nodiscard]]
inline auto ecdh_generate_key(  // NOLINT(readability-function-cognitive-complexity)
    const EcCurve curve)
    -> std::expected<EccKeyPair, CryptoError>
{
    if (psa_crypto_init() != PSA_SUCCESS) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InitFailed,
            "PSA crypto init failed"));
    }

    const psa_ecc_family_t family   = PSA_ECC_FAMILY_SECP_R1;
    const psa_key_bits_t   key_bits = ec_curve_key_bits(curve);

    psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attrs, PSA_KEY_TYPE_ECC_KEY_PAIR(family));
    psa_set_key_bits(&attrs, key_bits);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attrs, PSA_ALG_ECDH);

    mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
    if (psa_generate_key(&attrs, &key_id) != PSA_SUCCESS) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyGenerationFailed,
            "ECDH key generation failed"));
    }

    const std::size_t private_key_size =
        PSA_EXPORT_KEY_OUTPUT_SIZE(PSA_KEY_TYPE_ECC_KEY_PAIR(family), key_bits);
    SecureBuffer private_key_der(private_key_size);
    std::size_t  private_key_length = 0;

    if (psa_export_key(key_id,
                       private_key_der.data(),
                       private_key_der.size(),
                       &private_key_length) != PSA_SUCCESS) {
        psa_destroy_key(key_id);
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyExportFailed,
            "ECDH private key export failed"));
    }
    private_key_der.resize(private_key_length);

    const std::size_t public_key_size =
        PSA_EXPORT_PUBLIC_KEY_OUTPUT_SIZE(PSA_KEY_TYPE_ECC_KEY_PAIR(family), key_bits);
    SecureBuffer public_key_der(public_key_size);
    std::size_t  public_key_length = 0;

    if (psa_export_public_key(key_id,
                              public_key_der.data(),
                              public_key_der.size(),
                              &public_key_length) != PSA_SUCCESS) {
        psa_destroy_key(key_id);
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyExportFailed,
            "ECDH public key export failed"));
    }
    public_key_der.resize(public_key_length);

    psa_destroy_key(key_id);

    return EccKeyPair{
        .private_key_der = std::move(private_key_der),
        .public_key_der  = std::move(public_key_der),
    };
}


// Performs raw ECDH: imports our private key and the peer's public key, runs
// psa_raw_key_agreement, and returns the shared secret. The caller is
// responsible for passing the result through a KDF before use as a key.
template<SecureBufferLike PeerPublicKey>
[[nodiscard]]
auto ecdh_compute_shared_secret(  // NOLINT(readability-function-cognitive-complexity)
    const EccKeyPair& our_key_pair,
    const EcCurve     curve,
    const PeerPublicKey& peer_public_key_der)
    -> std::expected<SecureBuffer, CryptoError>
{
    if (psa_crypto_init() != PSA_SUCCESS) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InitFailed,
            "PSA crypto init failed"));
    }

    const psa_ecc_family_t family   = PSA_ECC_FAMILY_SECP_R1;
    const psa_key_bits_t   key_bits = ec_curve_key_bits(curve);

    psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attrs, PSA_KEY_TYPE_ECC_KEY_PAIR(family));
    psa_set_key_bits(&attrs, key_bits);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attrs, PSA_ALG_ECDH);

    mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
    if (psa_import_key(&attrs,
                       our_key_pair.private_key_der.data(),
                       our_key_pair.private_key_der.size(),
                       &key_id) != PSA_SUCCESS) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyImportFailed,
            "ECDH private key import failed"));
    }

    const std::size_t shared_secret_size =
        PSA_RAW_KEY_AGREEMENT_OUTPUT_SIZE(PSA_KEY_TYPE_ECC_KEY_PAIR(family), key_bits);
    SecureBuffer shared_secret(shared_secret_size);
    std::size_t  shared_secret_length = 0;

    const psa_status_t status = psa_raw_key_agreement(
        PSA_ALG_ECDH,
        key_id,
        peer_public_key_der.data(), peer_public_key_der.size(),
        shared_secret.data(), shared_secret.size(),
        &shared_secret_length);

    psa_destroy_key(key_id);

    if (status != PSA_SUCCESS) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyAgreementFailed,
            "ECDH key agreement failed"));
    }

    shared_secret.resize(shared_secret_length);
    return shared_secret;
}
