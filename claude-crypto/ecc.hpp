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

struct EccKeyPair {
    SecureBuffer private_key_der;
    SecureBuffer public_key_der;
};


template<typename PSA = RealPsaBackend>
[[nodiscard]]
auto ecdsa_generate_key_impl(  // NOLINT(readability-function-cognitive-complexity)
    const EcCurve curve)
    -> std::expected<EccKeyPair, CryptoError>
{
    if (PSA::crypto_init() != PSA_SUCCESS) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InitFailed,
            "PSA crypto init failed"));
    }

    const psa_ecc_family_t family   = PSA_ECC_FAMILY_SECP_R1;
    const auto key_bits = static_cast<psa_key_bits_t>(ec_curve_key_bits(curve));

    psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attrs, PSA_KEY_TYPE_ECC_KEY_PAIR(family));
    psa_set_key_bits(&attrs, key_bits);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_SIGN_MESSAGE |
                                    PSA_KEY_USAGE_VERIFY_MESSAGE |
                                    PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attrs, PSA_ALG_ECDSA(PSA_ALG_SHA_384));

    mbedtls_svc_key_id_t raw_key_id = MBEDTLS_SVC_KEY_ID_INIT;
    if (PSA::generate_key(&attrs, &raw_key_id) != PSA_SUCCESS) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyGenerationFailed,
            "ECDSA key generation failed"));
    }
    PsaKeyHandle<PSA> key_handle(raw_key_id);

    const std::size_t private_key_size =
        PSA_EXPORT_KEY_OUTPUT_SIZE(PSA_KEY_TYPE_ECC_KEY_PAIR(family), key_bits);
    SecureBuffer private_key_der(private_key_size);
    std::size_t  private_key_length = 0;

    if (PSA::export_key(key_handle.get(),
                        private_key_der.data(),
                        private_key_der.size(),
                        &private_key_length) != PSA_SUCCESS) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyExportFailed,
            "ECDSA private key export failed"));
    }
    private_key_der.resize(private_key_length);

    const std::size_t public_key_size =
        PSA_EXPORT_PUBLIC_KEY_OUTPUT_SIZE(PSA_KEY_TYPE_ECC_KEY_PAIR(family), key_bits);
    SecureBuffer public_key_der(public_key_size);
    std::size_t  public_key_length = 0;

    if (PSA::export_public_key(key_handle.get(),
                               public_key_der.data(),
                               public_key_der.size(),
                               &public_key_length) != PSA_SUCCESS) {
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


template<typename PSA = RealPsaBackend, SecureBufferLike Message>
[[nodiscard]]
auto ecdsa_sign_impl(  // NOLINT(readability-function-cognitive-complexity)
    const EccKeyPair& key_pair,
    const EcCurve curve,
    const Message& message)
    -> std::expected<SecureBuffer, CryptoError>
{
    if (PSA::crypto_init() != PSA_SUCCESS) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InitFailed,
            "PSA crypto init failed"));
    }

    const psa_ecc_family_t family   = PSA_ECC_FAMILY_SECP_R1;
    const auto key_bits = static_cast<psa_key_bits_t>(ec_curve_key_bits(curve));

    psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attrs, PSA_KEY_TYPE_ECC_KEY_PAIR(family));
    psa_set_key_bits(&attrs, key_bits);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attrs, PSA_ALG_ECDSA(PSA_ALG_SHA_384));

    mbedtls_svc_key_id_t raw_key_id = MBEDTLS_SVC_KEY_ID_INIT;
    if (PSA::import_key(&attrs,
                        key_pair.private_key_der.data(),
                        key_pair.private_key_der.size(),
                        &raw_key_id) != PSA_SUCCESS) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyImportFailed,
            "ECDSA private key import failed"));
    }
    PsaKeyHandle<PSA> key_handle(raw_key_id);

    const std::size_t signature_size =
        PSA_SIGN_OUTPUT_SIZE(PSA_KEY_TYPE_ECC_KEY_PAIR(family),
                             key_bits,
                             PSA_ALG_ECDSA(PSA_ALG_SHA_384));
    SecureBuffer signature(signature_size);
    std::size_t  signature_length = 0;

    const psa_status_t status = PSA::sign_message(
        key_handle.get(),
        PSA_ALG_ECDSA(PSA_ALG_SHA_384),
        message.data(), message.size(),
        signature.data(), signature.size(),
        &signature_length);

    if (status != PSA_SUCCESS) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::SigningFailed,
            "ECDSA signing failed"));
    }

    signature.resize(signature_length);
    return signature;
}


template<typename PSA = RealPsaBackend,
         SecureBufferLike Message, SecureBufferLike Signature>
[[nodiscard]]
auto ecdsa_verify_impl(  // NOLINT(readability-function-cognitive-complexity)
    const EccKeyPair& key_pair,
    const EcCurve curve,
    const Message& message,
    const Signature& signature)
    -> std::expected<bool, CryptoError>
{
    if (PSA::crypto_init() != PSA_SUCCESS) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InitFailed,
            "PSA crypto init failed"));
    }

    const psa_ecc_family_t family   = PSA_ECC_FAMILY_SECP_R1;
    const auto key_bits = static_cast<psa_key_bits_t>(ec_curve_key_bits(curve));

    psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attrs, PSA_KEY_TYPE_ECC_PUBLIC_KEY(family));
    psa_set_key_bits(&attrs, key_bits);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(&attrs, PSA_ALG_ECDSA(PSA_ALG_SHA_384));

    mbedtls_svc_key_id_t raw_key_id = MBEDTLS_SVC_KEY_ID_INIT;
    if (PSA::import_key(&attrs,
                        key_pair.public_key_der.data(),
                        key_pair.public_key_der.size(),
                        &raw_key_id) != PSA_SUCCESS) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyImportFailed,
            "ECDSA public key import failed"));
    }
    PsaKeyHandle<PSA> key_handle(raw_key_id);

    const psa_status_t status = PSA::verify_message(
        key_handle.get(),
        PSA_ALG_ECDSA(PSA_ALG_SHA_384),
        message.data(), message.size(),
        signature.data(), signature.size());

    if (status == PSA_ERROR_INVALID_SIGNATURE || status == PSA_ERROR_INVALID_ARGUMENT) {
        return false;
    }
    if (status != PSA_SUCCESS) {
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
    return ecdsa_sign_impl<RealPsaBackend>(key_pair, curve, message);
}

template<SecureBufferLike Message, SecureBufferLike Signature>
[[nodiscard]]
auto ecdsa_verify(
    const EccKeyPair& key_pair,
    const EcCurve curve,
    const Message& message,
    const Signature& signature)
    -> std::expected<bool, CryptoError>
{
    return ecdsa_verify_impl<RealPsaBackend>(key_pair, curve, message, signature);
}
