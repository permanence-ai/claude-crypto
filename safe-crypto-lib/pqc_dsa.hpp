/*
Copyright Permanence AI, 2026. All rights reserved.

*/

#pragma once

#include <array>
#include <cstddef>
#include <expected>
#include <span>

#include "crypto_error.hpp"
#include "crypto_provider.hpp"
#include "psa_backend.hpp"
#include "secure_buffer.hpp"
#include "slh_dsa_variant.hpp"


// High-level SLH-DSA (FIPS 205) sign/verify/keygen API.
//
// Key types carry the variant at compile time so buffer sizes are constexpr.
// Raw key bytes are stored in SecureBuffer so secrets are scrubbed on destruction.

template<SlhDsaVariant V>
struct SlhDsaKeyPair {
    SecureBuffer private_key;  // FIPS 205 raw format, scrubbed on destruction
    SecureBuffer public_key;
};

template<SlhDsaVariant V>
struct SlhDsaPublicKey {
    SecureBuffer public_key;
};


// Generate a fresh SLH-DSA key pair.
template<SlhDsaVariant V, CryptoProvider Provider = DefaultProvider>
[[nodiscard]]
auto slh_dsa_generate_key_impl()
    -> std::expected<SlhDsaKeyPair<V>, CryptoError>
{
    if (Provider::crypto_init() != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InitFailed,
            "Crypto init failed"));
    }

    auto attrs = Provider::make_slh_dsa_generate_attrs(V);
    auto raw_key_id = Provider::null_key_id();
    if (Provider::generate_key(&attrs, &raw_key_id) != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyGenerationFailed,
            "SLH-DSA key generation failed"));
    }
    const PsaKeyHandle<Provider> key_handle(raw_key_id);

    constexpr std::size_t priv_size = slh_dsa_private_key_size(V);
    constexpr std::size_t pub_size  = slh_dsa_public_key_size(V);

    SlhDsaKeyPair<V> kp{
        .private_key = SecureBuffer(priv_size),
        .public_key  = SecureBuffer(pub_size),
    };

    std::size_t priv_len = 0;
    if (Provider::export_key(key_handle.get(),
                             kp.private_key.data(), kp.private_key.size(),
                             &priv_len) != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyExportFailed,
            "SLH-DSA private key export failed"));
    }
    kp.private_key.resize(priv_len);

    std::size_t pub_len = 0;
    if (Provider::export_public_key(key_handle.get(),
                                    kp.public_key.data(), kp.public_key.size(),
                                    &pub_len) != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyExportFailed,
            "SLH-DSA public key export failed"));
    }
    kp.public_key.resize(pub_len);

    return kp;
}


// Sign a message with an SLH-DSA private key.  Returns the raw signature bytes.
template<SlhDsaVariant V, CryptoProvider Provider = DefaultProvider, SecureBufferLike Message>
[[nodiscard]]
auto slh_dsa_sign_impl(
    const SlhDsaKeyPair<V>& key_pair,
    const Message& message)
    -> std::expected<SecureBuffer, CryptoError>
{
    if (Provider::crypto_init() != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InitFailed,
            "Crypto init failed"));
    }

    auto attrs = Provider::make_slh_dsa_sign_attrs(V);
    auto raw_key_id = Provider::null_key_id();
    if (Provider::import_key(&attrs,
                             key_pair.private_key.data(),
                             key_pair.private_key.size(),
                             &raw_key_id) != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyImportFailed,
            "SLH-DSA private key import failed"));
    }
    const PsaKeyHandle<Provider> key_handle(raw_key_id);

    SecureBuffer signature(Provider::slh_dsa_sign_output_size(V));
    std::size_t sig_len = 0;

    const auto status = Provider::sign_message(
        key_handle.get(),
        Provider::alg_slh_dsa(V),
        message.data(), message.size(),
        signature.data(), signature.size(),
        &sig_len);

    if (status != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::SigningFailed,
            "SLH-DSA signing failed"));
    }
    signature.resize(sig_len);
    return signature;
}


// Verify an SLH-DSA signature.  Returns an error if the signature is invalid.
template<SlhDsaVariant V, CryptoProvider Provider = DefaultProvider,
         SecureBufferLike Message, SecureBufferLike Signature>
[[nodiscard]]
auto slh_dsa_verify_impl(
    const SlhDsaPublicKey<V>& public_key,
    const Message& message,
    const Signature& signature)
    -> std::expected<void, CryptoError>
{
    if (Provider::crypto_init() != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InitFailed,
            "Crypto init failed"));
    }

    auto attrs = Provider::make_slh_dsa_verify_attrs(V);
    auto raw_key_id = Provider::null_key_id();
    if (Provider::import_key(&attrs,
                             public_key.public_key.data(),
                             public_key.public_key.size(),
                             &raw_key_id) != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyImportFailed,
            "SLH-DSA public key import failed"));
    }
    const PsaKeyHandle<Provider> key_handle(raw_key_id);

    const auto status = Provider::verify_message(
        key_handle.get(),
        Provider::alg_slh_dsa(V),
        message.data(), message.size(),
        signature.data(), signature.size());

    if (status == Provider::err_invalid_sig) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::VerificationFailed,
            "SLH-DSA signature verification failed"));
    }
    if (status != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::VerificationFailed,
            "SLH-DSA verify error"));
    }
    return {};
}


// Convenience wrappers using the default provider.
template<SlhDsaVariant V>
[[nodiscard]] auto slh_dsa_generate_key()  { return slh_dsa_generate_key_impl<V>(); }

template<SlhDsaVariant V, SecureBufferLike Message>
[[nodiscard]] auto slh_dsa_sign(const SlhDsaKeyPair<V>& kp, const Message& msg) {
    return slh_dsa_sign_impl<V>(kp, msg);
}

template<SlhDsaVariant V, SecureBufferLike Message, SecureBufferLike Signature>
[[nodiscard]] auto slh_dsa_verify(const SlhDsaPublicKey<V>& pk, const Message& msg, const Signature& sig) {
    return slh_dsa_verify_impl<V>(pk, msg, sig);
}
