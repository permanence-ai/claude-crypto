// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstddef>
#include <expected>

#include "crypto_error.hpp"
#include "crypto_provider.hpp"
#include "ml_kem_variant.hpp"
#include "psa_backend.hpp"
#include "secure_buffer.hpp"


// High-level ML-KEM (FIPS 203) keygen/encapsulate/decapsulate API.
//
// ML-KEM is a key-encapsulation mechanism (KEM), not a signature scheme.
// Encapsulate takes a public key and produces a ciphertext + shared secret.
// Decapsulate takes a private key and a ciphertext and recovers the shared secret.

template<MlKemVariant V>
struct MlKemKeyPair {
    SecureBuffer private_key;  // FIPS 203 decapsulation key, scrubbed on destruction
    SecureBuffer public_key;   // FIPS 203 encapsulation key
};

template<MlKemVariant V>
struct MlKemPublicKey {
    SecureBuffer public_key;   // FIPS 203 encapsulation key
};

struct MlKemEncapResult {
    SecureBuffer ciphertext;    // sent to the decapsulating party
    SecureBuffer shared_secret; // kept locally, scrubbed on destruction
};


// Generate a fresh ML-KEM key pair.
template<MlKemVariant V, CryptoProvider Provider = DefaultProvider>
[[nodiscard]]
auto ml_kem_generate_key_impl()
    -> std::expected<MlKemKeyPair<V>, CryptoError>
{
    if (Provider::crypto_init() != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InitFailed,
            "Crypto init failed"));
    }

    auto attrs = Provider::make_ml_kem_generate_attrs(V);
    auto key_result = Provider::generate_key(&attrs);
    if (!key_result.has_value()) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyGenerationFailed,
            "ML-KEM key generation failed"));
    }
    const PsaKeyHandle<Provider> key_handle(key_result.value());

    constexpr std::size_t priv_size = ml_kem_private_key_size(V);
    constexpr std::size_t pub_size  = ml_kem_public_key_size(V);

    MlKemKeyPair<V> kp{
        .private_key = SecureBuffer(priv_size),
        .public_key  = SecureBuffer(pub_size),
    };

    std::size_t priv_len = 0;
    if (Provider::export_key(key_handle.get(),
                             kp.private_key.data(), kp.private_key.size(),
                             &priv_len) != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyExportFailed,
            "ML-KEM private key export failed"));
    }
    kp.private_key.resize(priv_len);

    std::size_t pub_len = 0;
    if (Provider::export_public_key(key_handle.get(),
                                    kp.public_key.data(), kp.public_key.size(),
                                    &pub_len) != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyExportFailed,
            "ML-KEM public key export failed"));
    }
    kp.public_key.resize(pub_len);

    return kp;
}


// Encapsulate: generate a shared secret and encrypt it under a public key.
// Returns the ciphertext (to send to peer) and the shared secret (to keep).
template<MlKemVariant V, CryptoProvider Provider = DefaultProvider>
[[nodiscard]]
auto ml_kem_encapsulate_impl(const MlKemPublicKey<V>& public_key)
    -> std::expected<MlKemEncapResult, CryptoError>
{
    if (public_key.public_key.size() != ml_kem_public_key_size(V)) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InvalidArgument,
            "ML-KEM public key has wrong size"));
    }
    if (Provider::crypto_init() != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InitFailed,
            "Crypto init failed"));
    }

    auto attrs = Provider::make_ml_kem_encap_attrs(V);
    auto key_result = Provider::import_key(&attrs,
                             public_key.public_key.data(),
                             public_key.public_key.size());
    if (!key_result.has_value()) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyImportFailed,
            "ML-KEM public key import failed"));
    }
    const PsaKeyHandle<Provider> key_handle(key_result.value());

    MlKemEncapResult result{
        .ciphertext    = SecureBuffer(Provider::ml_kem_ciphertext_size(V)),
        .shared_secret = SecureBuffer(Provider::ml_kem_shared_secret_size(V)),
    };
    std::size_t ct_len = 0;
    std::size_t ss_len = 0;

    const auto status = Provider::kem_encapsulate(
        key_handle.get(),
        Provider::alg_ml_kem(V),
        result.ciphertext.data(), result.ciphertext.size(), &ct_len,
        result.shared_secret.data(), result.shared_secret.size(), &ss_len);

    if (status != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::EncapsulationFailed,
            "ML-KEM encapsulation failed"));
    }
    result.ciphertext.resize(ct_len);
    result.shared_secret.resize(ss_len);
    return result;
}


// Decapsulate: recover the shared secret from a ciphertext using a private key.
template<MlKemVariant V, CryptoProvider Provider = DefaultProvider, SecureBufferLike Ciphertext>
[[nodiscard]]
auto ml_kem_decapsulate_impl(
    const MlKemKeyPair<V>& key_pair,
    const Ciphertext& ciphertext)
    -> std::expected<SecureBuffer, CryptoError>
{
    if (key_pair.private_key.size() != ml_kem_private_key_size(V)) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InvalidArgument,
            "ML-KEM private key has wrong size"));
    }
    if (ciphertext.size() != ml_kem_ciphertext_size(V)) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InvalidArgument,
            "ML-KEM ciphertext has wrong size"));
    }
    if (Provider::crypto_init() != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InitFailed,
            "Crypto init failed"));
    }

    auto attrs = Provider::make_ml_kem_decap_attrs(V);
    auto key_result = Provider::import_key(&attrs,
                             key_pair.private_key.data(),
                             key_pair.private_key.size());
    if (!key_result.has_value()) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyImportFailed,
            "ML-KEM private key import failed"));
    }
    const PsaKeyHandle<Provider> key_handle(key_result.value());

    SecureBuffer shared_secret(Provider::ml_kem_shared_secret_size(V));
    std::size_t ss_len = 0;

    const auto status = Provider::kem_decapsulate(
        key_handle.get(),
        Provider::alg_ml_kem(V),
        ciphertext.data(), ciphertext.size(),
        shared_secret.data(), shared_secret.size(), &ss_len);

    if (status != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::DecapsulationFailed,
            "ML-KEM decapsulation failed"));
    }
    shared_secret.resize(ss_len);
    return shared_secret;
}


// Convenience wrappers using the default provider.
template<MlKemVariant V>
[[nodiscard]] auto ml_kem_generate_key() { return ml_kem_generate_key_impl<V>(); }

template<MlKemVariant V>
[[nodiscard]] auto ml_kem_encapsulate(const MlKemPublicKey<V>& pk) {
    return ml_kem_encapsulate_impl<V>(pk);
}

template<MlKemVariant V, SecureBufferLike Ciphertext>
[[nodiscard]] auto ml_kem_decapsulate(const MlKemKeyPair<V>& kp, const Ciphertext& ct) {
    return ml_kem_decapsulate_impl<V>(kp, ct);
}
