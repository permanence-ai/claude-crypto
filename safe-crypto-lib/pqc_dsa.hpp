// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <array>
#include <cstddef>
#include <expected>
#include <span>

#include "crypto_error.hpp"
#include "crypto_log.hpp"
#include "crypto_provider.hpp"
#include "ml_dsa_variant.hpp"
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
    auto key_result = Provider::generate_key(&attrs);
    if (!key_result.has_value()) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyGenerationFailed,
            "SLH-DSA key generation failed"));
    }
    const PsaKeyHandle<Provider> key_handle(key_result.value());

    auto priv_result = Provider::export_key(key_handle.get());
    if (!priv_result.has_value()) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyExportFailed,
            "SLH-DSA private key export failed"));
    }

    auto pub_result = Provider::export_public_key(key_handle.get());
    if (!pub_result.has_value()) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyExportFailed,
            "SLH-DSA public key export failed"));
    }

    return SlhDsaKeyPair<V>{
        .private_key = std::move(priv_result).value(),
        .public_key  = std::move(pub_result).value(),
    };
}


// Sign a message with an SLH-DSA private key.  Returns the raw signature bytes.
template<SlhDsaVariant V, CryptoProvider Provider = DefaultProvider, SecureBufferLike Message>
[[nodiscard]]
auto slh_dsa_sign_impl(
    const SlhDsaKeyPair<V>& key_pair,
    const Message& message)
    -> std::expected<SecureBuffer, CryptoError>
{
    if (key_pair.private_key.size() != slh_dsa_private_key_size(V)) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InvalidArgument,
            "SLH-DSA private key has wrong size"));
    }
    if (Provider::crypto_init() != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InitFailed,
            "Crypto init failed"));
    }

    auto attrs = Provider::make_slh_dsa_sign_attrs(V);
    auto key_result = Provider::import_key(&attrs,
                             CByteVSpan{key_pair.private_key.data(),
                                        key_pair.private_key.size()});
    if (!key_result.has_value()) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyImportFailed,
            "SLH-DSA private key import failed"));
    }
    const PsaKeyHandle<Provider> key_handle(key_result.value());

    auto sig_result = Provider::sign_message(
        key_handle.get(),
        Provider::alg_slh_dsa(V),
        CByteVSpan{message.data(), message.size()});

    if (!sig_result.has_value()) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::SigningFailed,
            "SLH-DSA signing failed"));
    }

    return std::move(sig_result).value();
}


// Verify an SLH-DSA signature.  Returns false for an invalid signature,
// or an unexpected error only for processing failures (key import, init).
template<SlhDsaVariant V, CryptoProvider Provider = DefaultProvider,
         SecureBufferLike Message, SecureBufferLike Signature>
[[nodiscard]]
auto slh_dsa_verify_impl(
    const SlhDsaPublicKey<V>& public_key,
    const Message& message,
    const Signature& signature)
    -> std::expected<bool, CryptoError>
{
    if (public_key.public_key.size() != slh_dsa_public_key_size(V)) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InvalidArgument,
            "SLH-DSA public key has wrong size"));
    }
    if (signature.size() != slh_dsa_signature_size(V)) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InvalidArgument,
            "SLH-DSA signature has wrong size"));
    }
    if (Provider::crypto_init() != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InitFailed,
            "Crypto init failed"));
    }

    auto attrs = Provider::make_slh_dsa_verify_attrs(V);
    auto key_result = Provider::import_key(&attrs,
                             CByteVSpan{public_key.public_key.data(),
                                        public_key.public_key.size()});
    if (!key_result.has_value()) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyImportFailed,
            "SLH-DSA public key import failed"));
    }
    const PsaKeyHandle<Provider> key_handle(key_result.value());

    const auto status = Provider::verify_message(
        key_handle.get(),
        Provider::alg_slh_dsa(V),
        CByteVSpan{message.data(), message.size()},
        CByteVSpan{signature.data(), signature.size()});

    if (status == Provider::err_invalid_sig) {
        return false;
    }
    if (status != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::VerificationFailed,
            "SLH-DSA verify error"));
    }
    return true;
}


// Convenience wrappers using the default provider.
template<SlhDsaVariant V>
[[nodiscard]] auto slh_dsa_generate_key() {
    if (crypto_log_enabled(CryptoLogLevel::Debug)) {
        crypto_log(CryptoLogLevel::Debug, "slh_dsa_generate_key: entry");
    }
    auto result = slh_dsa_generate_key_impl<V>();
    if (!result.has_value()) {
        crypto_log(CryptoLogLevel::Error, "slh_dsa_generate_key: " + result.error().message());
    } else if (crypto_log_enabled(CryptoLogLevel::Debug)) {
        crypto_log(CryptoLogLevel::Debug, crypto_log_detail::msg("slh_dsa_generate_key", "priv", result->private_key.size(), "pub", result->public_key.size()));
    }
    return result;
}

template<SlhDsaVariant V, SecureBufferLike Message>
[[nodiscard]] auto slh_dsa_sign(const SlhDsaKeyPair<V>& kp, const Message& msg) {
    if (crypto_log_enabled(CryptoLogLevel::Debug)) {
        crypto_log(CryptoLogLevel::Debug, crypto_log_detail::msg("slh_dsa_sign", "msg", msg.size()));
    }
    auto result = slh_dsa_sign_impl<V>(kp, msg);
    if (!result.has_value()) {
        crypto_log(CryptoLogLevel::Error, "slh_dsa_sign: " + result.error().message());
    } else if (crypto_log_enabled(CryptoLogLevel::Debug)) {
        crypto_log(CryptoLogLevel::Debug, crypto_log_detail::msg("slh_dsa_sign", "sig", result->size()));
    }
    return result;
}

template<SlhDsaVariant V, SecureBufferLike Message, SecureBufferLike Signature>
[[nodiscard]] auto slh_dsa_verify(const SlhDsaPublicKey<V>& pk, const Message& msg, const Signature& sig) {
    if (crypto_log_enabled(CryptoLogLevel::Debug)) {
        crypto_log(CryptoLogLevel::Debug, crypto_log_detail::msg("slh_dsa_verify", "msg", msg.size(), "sig", sig.size()));
    }
    auto result = slh_dsa_verify_impl<V>(pk, msg, sig);
    if (!result.has_value()) {
        crypto_log(CryptoLogLevel::Error, "slh_dsa_verify: " + result.error().message());
    } else if (crypto_log_enabled(CryptoLogLevel::Debug)) {
        crypto_log(CryptoLogLevel::Debug, result.value() ? "slh_dsa_verify: ok" : "slh_dsa_verify: mismatch");
    }
    return result;
}


// Zero-parameter wrappers using NIST-recommended parameter sets.
// SLH-DSA-SHA2-128s (security level 1, small signatures) is the recommended general-purpose choice.
[[nodiscard]] inline auto slh_dsa_generate_key() {
    if (crypto_log_enabled(CryptoLogLevel::Debug)) {
        crypto_log(CryptoLogLevel::Debug, "slh_dsa_generate_key: entry");
    }
    auto result = slh_dsa_generate_key_impl<SlhDsaVariant::Sha2_128s>();
    if (!result.has_value()) {
        crypto_log(CryptoLogLevel::Error, "slh_dsa_generate_key: " + result.error().message());
    } else if (crypto_log_enabled(CryptoLogLevel::Debug)) {
        crypto_log(CryptoLogLevel::Debug, crypto_log_detail::msg("slh_dsa_generate_key", "priv", result->private_key.size(), "pub", result->public_key.size()));
    }
    return result;
}

template<SecureBufferLike Message>
[[nodiscard]] auto slh_dsa_sign(const SlhDsaKeyPair<SlhDsaVariant::Sha2_128s>& kp, const Message& msg) {
    if (crypto_log_enabled(CryptoLogLevel::Debug)) {
        crypto_log(CryptoLogLevel::Debug, crypto_log_detail::msg("slh_dsa_sign", "msg", msg.size()));
    }
    auto result = slh_dsa_sign_impl<SlhDsaVariant::Sha2_128s>(kp, msg);
    if (!result.has_value()) {
        crypto_log(CryptoLogLevel::Error, "slh_dsa_sign: " + result.error().message());
    } else if (crypto_log_enabled(CryptoLogLevel::Debug)) {
        crypto_log(CryptoLogLevel::Debug, crypto_log_detail::msg("slh_dsa_sign", "sig", result->size()));
    }
    return result;
}

template<SecureBufferLike Message, SecureBufferLike Signature>
[[nodiscard]] auto slh_dsa_verify(const SlhDsaPublicKey<SlhDsaVariant::Sha2_128s>& pk, const Message& msg, const Signature& sig) {
    if (crypto_log_enabled(CryptoLogLevel::Debug)) {
        crypto_log(CryptoLogLevel::Debug, crypto_log_detail::msg("slh_dsa_verify", "msg", msg.size(), "sig", sig.size()));
    }
    auto result = slh_dsa_verify_impl<SlhDsaVariant::Sha2_128s>(pk, msg, sig);
    if (!result.has_value()) {
        crypto_log(CryptoLogLevel::Error, "slh_dsa_verify: " + result.error().message());
    } else if (crypto_log_enabled(CryptoLogLevel::Debug)) {
        crypto_log(CryptoLogLevel::Debug, result.value() ? "slh_dsa_verify: ok" : "slh_dsa_verify: mismatch");
    }
    return result;
}


// High-level ML-DSA (FIPS 204) sign/verify/keygen API.
//
// Mirrors the SLH-DSA API above.  Variant is encoded at compile time in the
// type so buffer sizes are constexpr.  Secrets are scrubbed on destruction.

template<MlDsaVariant V>
struct MlDsaKeyPair {
    SecureBuffer private_key;  // FIPS 204 raw format, scrubbed on destruction
    SecureBuffer public_key;
};

template<MlDsaVariant V>
struct MlDsaPublicKey {
    SecureBuffer public_key;
};


// Generate a fresh ML-DSA key pair.
template<MlDsaVariant V, CryptoProvider Provider = DefaultProvider>
[[nodiscard]]
auto ml_dsa_generate_key_impl()
    -> std::expected<MlDsaKeyPair<V>, CryptoError>
{
    if (Provider::crypto_init() != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InitFailed,
            "Crypto init failed"));
    }

    auto attrs = Provider::make_ml_dsa_generate_attrs(V);
    auto key_result = Provider::generate_key(&attrs);
    if (!key_result.has_value()) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyGenerationFailed,
            "ML-DSA key generation failed"));
    }
    const PsaKeyHandle<Provider> key_handle(key_result.value());

    auto priv_result = Provider::export_key(key_handle.get());
    if (!priv_result.has_value()) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyExportFailed,
            "ML-DSA private key export failed"));
    }

    auto pub_result = Provider::export_public_key(key_handle.get());
    if (!pub_result.has_value()) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyExportFailed,
            "ML-DSA public key export failed"));
    }

    return MlDsaKeyPair<V>{
        .private_key = std::move(priv_result).value(),
        .public_key  = std::move(pub_result).value(),
    };
}


// Sign a message with an ML-DSA private key.  Returns the raw signature bytes.
template<MlDsaVariant V, CryptoProvider Provider = DefaultProvider, SecureBufferLike Message>
[[nodiscard]]
auto ml_dsa_sign_impl(
    const MlDsaKeyPair<V>& key_pair,
    const Message& message)
    -> std::expected<SecureBuffer, CryptoError>
{
    if (key_pair.private_key.size() != ml_dsa_private_key_size(V)) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InvalidArgument,
            "ML-DSA private key has wrong size"));
    }
    if (Provider::crypto_init() != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InitFailed,
            "Crypto init failed"));
    }

    auto attrs = Provider::make_ml_dsa_sign_attrs(V);
    auto key_result = Provider::import_key(&attrs,
                             CByteVSpan{key_pair.private_key.data(),
                                        key_pair.private_key.size()});
    if (!key_result.has_value()) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyImportFailed,
            "ML-DSA private key import failed"));
    }
    const PsaKeyHandle<Provider> key_handle(key_result.value());

    auto sig_result = Provider::sign_message(
        key_handle.get(),
        Provider::alg_ml_dsa(V),
        CByteVSpan{message.data(), message.size()});

    if (!sig_result.has_value()) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::SigningFailed,
            "ML-DSA signing failed"));
    }

    return std::move(sig_result).value();
}


// Verify an ML-DSA signature.  Returns false for an invalid signature,
// or an unexpected error only for processing failures (key import, init).
template<MlDsaVariant V, CryptoProvider Provider = DefaultProvider,
         SecureBufferLike Message, SecureBufferLike Signature>
[[nodiscard]]
auto ml_dsa_verify_impl(
    const MlDsaPublicKey<V>& public_key,
    const Message& message,
    const Signature& signature)
    -> std::expected<bool, CryptoError>
{
    if (public_key.public_key.size() != ml_dsa_public_key_size(V)) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InvalidArgument,
            "ML-DSA public key has wrong size"));
    }
    if (signature.size() != ml_dsa_signature_size(V)) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InvalidArgument,
            "ML-DSA signature has wrong size"));
    }
    if (Provider::crypto_init() != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InitFailed,
            "Crypto init failed"));
    }

    auto attrs = Provider::make_ml_dsa_verify_attrs(V);
    auto key_result = Provider::import_key(&attrs,
                             CByteVSpan{public_key.public_key.data(),
                                        public_key.public_key.size()});
    if (!key_result.has_value()) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyImportFailed,
            "ML-DSA public key import failed"));
    }
    const PsaKeyHandle<Provider> key_handle(key_result.value());

    const auto status = Provider::verify_message(
        key_handle.get(),
        Provider::alg_ml_dsa(V),
        CByteVSpan{message.data(), message.size()},
        CByteVSpan{signature.data(), signature.size()});

    if (status == Provider::err_invalid_sig) {
        return false;
    }
    if (status != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::VerificationFailed,
            "ML-DSA verify error"));
    }
    return true;
}


// Convenience wrappers using the default provider.
template<MlDsaVariant V>
[[nodiscard]] auto ml_dsa_generate_key() {
    if (crypto_log_enabled(CryptoLogLevel::Debug)) {
        crypto_log(CryptoLogLevel::Debug, "ml_dsa_generate_key: entry");
    }
    auto result = ml_dsa_generate_key_impl<V>();
    if (!result.has_value()) {
        crypto_log(CryptoLogLevel::Error, "ml_dsa_generate_key: " + result.error().message());
    } else if (crypto_log_enabled(CryptoLogLevel::Debug)) {
        crypto_log(CryptoLogLevel::Debug, crypto_log_detail::msg("ml_dsa_generate_key", "priv", result->private_key.size(), "pub", result->public_key.size()));
    }
    return result;
}

template<MlDsaVariant V, SecureBufferLike Message>
[[nodiscard]] auto ml_dsa_sign(const MlDsaKeyPair<V>& kp, const Message& msg) {
    if (crypto_log_enabled(CryptoLogLevel::Debug)) {
        crypto_log(CryptoLogLevel::Debug, crypto_log_detail::msg("ml_dsa_sign", "msg", msg.size()));
    }
    auto result = ml_dsa_sign_impl<V>(kp, msg);
    if (!result.has_value()) {
        crypto_log(CryptoLogLevel::Error, "ml_dsa_sign: " + result.error().message());
    } else if (crypto_log_enabled(CryptoLogLevel::Debug)) {
        crypto_log(CryptoLogLevel::Debug, crypto_log_detail::msg("ml_dsa_sign", "sig", result->size()));
    }
    return result;
}

template<MlDsaVariant V, SecureBufferLike Message, SecureBufferLike Signature>
[[nodiscard]] auto ml_dsa_verify(const MlDsaPublicKey<V>& pk, const Message& msg, const Signature& sig) {
    if (crypto_log_enabled(CryptoLogLevel::Debug)) {
        crypto_log(CryptoLogLevel::Debug, crypto_log_detail::msg("ml_dsa_verify", "msg", msg.size(), "sig", sig.size()));
    }
    auto result = ml_dsa_verify_impl<V>(pk, msg, sig);
    if (!result.has_value()) {
        crypto_log(CryptoLogLevel::Error, "ml_dsa_verify: " + result.error().message());
    } else if (crypto_log_enabled(CryptoLogLevel::Debug)) {
        crypto_log(CryptoLogLevel::Debug, result.value() ? "ml_dsa_verify: ok" : "ml_dsa_verify: mismatch");
    }
    return result;
}


// Zero-parameter wrappers using NIST-recommended parameter sets.
// ML-DSA-65 (security level 3, 192-bit) is the recommended general-purpose choice.
[[nodiscard]] inline auto ml_dsa_generate_key() {
    if (crypto_log_enabled(CryptoLogLevel::Debug)) {
        crypto_log(CryptoLogLevel::Debug, "ml_dsa_generate_key: entry");
    }
    auto result = ml_dsa_generate_key_impl<MlDsaVariant::Dsa65>();
    if (!result.has_value()) {
        crypto_log(CryptoLogLevel::Error, "ml_dsa_generate_key: " + result.error().message());
    } else if (crypto_log_enabled(CryptoLogLevel::Debug)) {
        crypto_log(CryptoLogLevel::Debug, crypto_log_detail::msg("ml_dsa_generate_key", "priv", result->private_key.size(), "pub", result->public_key.size()));
    }
    return result;
}

template<SecureBufferLike Message>
[[nodiscard]] auto ml_dsa_sign(const MlDsaKeyPair<MlDsaVariant::Dsa65>& kp, const Message& msg) {
    if (crypto_log_enabled(CryptoLogLevel::Debug)) {
        crypto_log(CryptoLogLevel::Debug, crypto_log_detail::msg("ml_dsa_sign", "msg", msg.size()));
    }
    auto result = ml_dsa_sign_impl<MlDsaVariant::Dsa65>(kp, msg);
    if (!result.has_value()) {
        crypto_log(CryptoLogLevel::Error, "ml_dsa_sign: " + result.error().message());
    } else if (crypto_log_enabled(CryptoLogLevel::Debug)) {
        crypto_log(CryptoLogLevel::Debug, crypto_log_detail::msg("ml_dsa_sign", "sig", result->size()));
    }
    return result;
}

template<SecureBufferLike Message, SecureBufferLike Signature>
[[nodiscard]] auto ml_dsa_verify(const MlDsaPublicKey<MlDsaVariant::Dsa65>& pk, const Message& msg, const Signature& sig) {
    if (crypto_log_enabled(CryptoLogLevel::Debug)) {
        crypto_log(CryptoLogLevel::Debug, crypto_log_detail::msg("ml_dsa_verify", "msg", msg.size(), "sig", sig.size()));
    }
    auto result = ml_dsa_verify_impl<MlDsaVariant::Dsa65>(pk, msg, sig);
    if (!result.has_value()) {
        crypto_log(CryptoLogLevel::Error, "ml_dsa_verify: " + result.error().message());
    } else if (crypto_log_enabled(CryptoLogLevel::Debug)) {
        crypto_log(CryptoLogLevel::Debug, result.value() ? "ml_dsa_verify: ok" : "ml_dsa_verify: mismatch");
    }
    return result;
}
