/*
Copyright Permanence AI, 2026. All rights reserved.

*/

#pragma once

#include <cstddef>
#include <expected>
#include <optional>

#include "asymmetric.hpp"
#include "contracts.hpp"
#include "crypto_error.hpp"
#include "defs.hpp"
#include "psa_backend.hpp"
#include "random.hpp"
#include "secure_buffer.hpp"


template<CryptoProvider Provider = RealPsaBackend>
[[nodiscard]]
auto derive_key_impl(  // NOLINT(readability-function-cognitive-complexity)
    const std::size_t output_length,
    const std::optional<SecureBuffer>& ikm  = std::nullopt,
    const std::optional<SecureBuffer>& salt = std::nullopt,
    const std::optional<SecureBuffer>& info = std::nullopt)
    SAFE_CRYPTO_PRE(output_length > 0)
    -> std::expected<SecureBuffer, CryptoError>
{
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

    auto attrs = Provider::make_hkdf_derive_attrs(ikm_ref.size() * bits_per_byte);

    auto raw_key_id = Provider::null_key_id();
    if (Provider::import_key(&attrs, ikm_ref.data(), ikm_ref.size(), &raw_key_id) != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyImportFailed,
            "IKM import failed"));
    }
    const PsaKeyHandle<Provider> key_handle(raw_key_id);

    auto op = Provider::make_kdf_op();

    if (Provider::key_derivation_setup(&op, Provider::alg_hkdf()) != Provider::ok) {
        Provider::key_derivation_abort(&op);
        return std::unexpected(CryptoError(
            CryptoErrorCode::KdfSetupFailed,
            "HKDF setup failed"));
    }

    if (salt.has_value()) {
        if (Provider::key_derivation_input_bytes(&op, Provider::kdf_step_salt(),
                                            salt->data(), salt->size()) != Provider::ok) {
            Provider::key_derivation_abort(&op);
            return std::unexpected(CryptoError(
                CryptoErrorCode::KdfInputFailed,
                "HKDF salt input failed"));
        }
    }

    if (Provider::key_derivation_input_key(&op, Provider::kdf_step_secret(),
                                      key_handle.get()) != Provider::ok) {
        Provider::key_derivation_abort(&op);
        return std::unexpected(CryptoError(
            CryptoErrorCode::KdfInputFailed,
            "HKDF secret input failed"));
    }

    if (info.has_value()) {
        if (Provider::key_derivation_input_bytes(&op, Provider::kdf_step_info(),
                                            info->data(), info->size()) != Provider::ok) {
            Provider::key_derivation_abort(&op);
            return std::unexpected(CryptoError(
                CryptoErrorCode::KdfInputFailed,
                "HKDF info input failed"));
        }
    } else {
        if (Provider::key_derivation_input_bytes(&op, Provider::kdf_step_info(),
                                            nullptr, 0) != Provider::ok) {
            Provider::key_derivation_abort(&op);
            return std::unexpected(CryptoError(
                CryptoErrorCode::KdfInputFailed,
                "HKDF info input failed"));
        }
    }

    SecureBuffer output(output_length);
    if (Provider::key_derivation_output_bytes(&op, output.data(), output.size()) != Provider::ok) {
        Provider::key_derivation_abort(&op);
        return std::unexpected(CryptoError(
            CryptoErrorCode::KdfOutputFailed,
            "HKDF output failed"));
    }

    Provider::key_derivation_abort(&op);
    return output;
}


template<CryptoProvider Provider = RealPsaBackend>
[[nodiscard]]
auto expand_key_impl(  // NOLINT(readability-function-cognitive-complexity)
    const std::size_t output_length,
    const SecureBuffer& prk,
    const std::optional<SecureBuffer>& info = std::nullopt)
    SAFE_CRYPTO_PRE(output_length > 0)
    -> std::expected<SecureBuffer, CryptoError>
{
    if (Provider::crypto_init() != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InitFailed,
            "PSA crypto init failed"));
    }

    auto attrs = Provider::make_hkdf_expand_derive_attrs(prk.size() * bits_per_byte);

    auto raw_key_id = Provider::null_key_id();
    if (Provider::import_key(&attrs, prk.data(), prk.size(), &raw_key_id) != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyImportFailed,
            "PRK import failed"));
    }
    const PsaKeyHandle<Provider> key_handle(raw_key_id);

    auto op = Provider::make_kdf_op();

    if (Provider::key_derivation_setup(&op, Provider::alg_hkdf_expand()) != Provider::ok) {
        Provider::key_derivation_abort(&op);
        return std::unexpected(CryptoError(
            CryptoErrorCode::KdfSetupFailed,
            "HKDF-Expand setup failed"));
    }

    if (Provider::key_derivation_input_key(&op, Provider::kdf_step_secret(),
                                      key_handle.get()) != Provider::ok) {
        Provider::key_derivation_abort(&op);
        return std::unexpected(CryptoError(
            CryptoErrorCode::KdfInputFailed,
            "HKDF-Expand PRK input failed"));
    }

    const CryptoByte* info_ptr  = info.has_value() ? info->data() : nullptr;
    const std::size_t   info_size = info.has_value() ? info->size() : 0;

    if (Provider::key_derivation_input_bytes(&op, Provider::kdf_step_info(),
                                        info_ptr, info_size) != Provider::ok) {
        Provider::key_derivation_abort(&op);
        return std::unexpected(CryptoError(
            CryptoErrorCode::KdfInputFailed,
            "HKDF-Expand info input failed"));
    }

    SecureBuffer output(output_length);
    if (Provider::key_derivation_output_bytes(&op, output.data(), output.size()) != Provider::ok) {
        Provider::key_derivation_abort(&op);
        return std::unexpected(CryptoError(
            CryptoErrorCode::KdfOutputFailed,
            "HKDF-Expand output failed"));
    }

    Provider::key_derivation_abort(&op);
    return output;
}


[[nodiscard]]
inline auto derive_key(
    const std::size_t output_length,
    const std::optional<SecureBuffer>& ikm  = std::nullopt,
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


template<RsaKeyBits KB, CryptoProvider Provider = RealPsaBackend>
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

    auto raw_key_id = Provider::null_key_id();
    if (Provider::generate_key(&attrs, &raw_key_id) != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyGenerationFailed,
            "RSA key generation failed"));
    }
    const PsaKeyHandle<Provider> key_handle(raw_key_id);

    SecureBuffer private_key_der(Provider::rsa_private_key_export_size(key_bits_val));
    std::size_t private_key_length = 0;

    if (Provider::export_key(key_handle.get(),
                        private_key_der.data(),
                        private_key_der.size(),
                        &private_key_length) != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyExportFailed,
            "RSA private key export failed"));
    }
    private_key_der.resize(private_key_length);

    SecureBuffer public_key_der(Provider::rsa_public_key_export_size(key_bits_val));
    std::size_t public_key_length = 0;

    if (Provider::export_public_key(key_handle.get(),
                               public_key_der.data(),
                               public_key_der.size(),
                               &public_key_length) != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyExportFailed,
            "RSA public key export failed"));
    }
    public_key_der.resize(public_key_length);

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
