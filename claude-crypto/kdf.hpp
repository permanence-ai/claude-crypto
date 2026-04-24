/*
Copyright Permanence AI, 2026. All rights reserved.

*/

#pragma once

#include <cstddef>
#include <expected>
#include <optional>

#include <psa/crypto.h>
#include <psa/crypto_values.h>

#include "asymmetric.hpp"
#include "crypto_error.hpp"
#include "random.hpp"
#include "secure_buffer.hpp"


[[nodiscard]]
inline auto derive_key(const std::size_t output_length,
                       const std::optional<SecureBuffer>& ikm  = std::nullopt,
                       const std::optional<SecureBuffer>& salt = std::nullopt,
                       const std::optional<SecureBuffer>& info = std::nullopt)
    -> std::expected<SecureBuffer, CryptoError>
{
    if (ikm.has_value() && ikm->size() < output_length * 2) {
        return std::unexpected(CryptoError("IKM must be at least 2 * output_length"));
    }

    if (psa_crypto_init() != PSA_SUCCESS) {
        return std::unexpected(CryptoError("PSA crypto init failed"));
    }

    // Generate IKM if not provided: twice the target key length per security convention
    auto generated_ikm = std::optional<SecureBuffer>{};
    if (!ikm.has_value()) {
        auto result = random_bytes(output_length * 2);
        if (!result.has_value()) {
            return std::unexpected(result.error());
        }
        generated_ikm = std::move(*result);
    }
    const SecureBuffer& ikm_ref = ikm.has_value() ? *ikm : *generated_ikm;

    psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attrs, PSA_KEY_TYPE_DERIVE);
    psa_set_key_bits(&attrs, static_cast<psa_key_bits_t>(ikm_ref.size() * 8));
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attrs, PSA_ALG_HKDF(PSA_ALG_SHA_384));

    mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
    if (psa_import_key(&attrs, ikm_ref.data(), ikm_ref.size(), &key_id) != PSA_SUCCESS) {
        return std::unexpected(CryptoError("IKM import failed"));
    }

    psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;

    auto cleanup = [&]()
    {
        psa_key_derivation_abort(&op);
        psa_destroy_key(key_id);
    };

    if (psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_384)) != PSA_SUCCESS) {
        cleanup();
        return std::unexpected(CryptoError("HKDF setup failed"));
    }

    if (salt.has_value()) {
        if (psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT,
                                           salt->data(), salt->size()) != PSA_SUCCESS) {
            cleanup();
            return std::unexpected(CryptoError("HKDF salt input failed"));
        }
    }

    if (psa_key_derivation_input_key(&op, PSA_KEY_DERIVATION_INPUT_SECRET,
                                     key_id) != PSA_SUCCESS) {
        cleanup();
        return std::unexpected(CryptoError("HKDF secret input failed"));
    }

    if (info.has_value()) {
        if (psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_INFO,
                                           info->data(), info->size()) != PSA_SUCCESS) {
            cleanup();
            return std::unexpected(CryptoError("HKDF info input failed"));
        }
    } else {
        if (psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_INFO,
                                           nullptr, 0) != PSA_SUCCESS) {
            cleanup();
            return std::unexpected(CryptoError("HKDF info input failed"));
        }
    }

    SecureBuffer output(output_length);
    if (psa_key_derivation_output_bytes(&op, output.data(), output.size()) != PSA_SUCCESS) {
        cleanup();
        return std::unexpected(CryptoError("HKDF output failed"));
    }

    cleanup();
    return output;
}


template<RsaKeyBits KB>
[[nodiscard]]
inline auto generate_rsa_key()  // NOLINT(readability-function-cognitive-complexity)
    -> std::expected<RsaKeyPair<KB>, CryptoError>
{
    if (psa_crypto_init() != PSA_SUCCESS) {
        return std::unexpected(CryptoError("PSA crypto init failed"));
    }

    constexpr auto key_bits_val = static_cast<psa_key_bits_t>(KB);

    psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attrs, PSA_KEY_TYPE_RSA_KEY_PAIR);
    psa_set_key_bits(&attrs, key_bits_val);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT |
                                    PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attrs, PSA_ALG_RSA_OAEP(PSA_ALG_SHA_384));

    mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
    if (psa_generate_key(&attrs, &key_id) != PSA_SUCCESS) {
        return std::unexpected(CryptoError("RSA key generation failed"));
    }

    const std::size_t private_key_size =
        PSA_EXPORT_KEY_OUTPUT_SIZE(PSA_KEY_TYPE_RSA_KEY_PAIR, key_bits_val);
    SecureBuffer private_key_der(private_key_size);
    std::size_t private_key_length = 0;

    if (psa_export_key(key_id,
                       private_key_der.data(),
                       private_key_der.size(),
                       &private_key_length) != PSA_SUCCESS) {
        psa_destroy_key(key_id);
        return std::unexpected(CryptoError("RSA private key export failed"));
    }
    private_key_der.resize(private_key_length);

    const std::size_t public_key_size =
        PSA_EXPORT_PUBLIC_KEY_OUTPUT_SIZE(PSA_KEY_TYPE_RSA_KEY_PAIR, key_bits_val);
    SecureBuffer public_key_der(public_key_size);
    std::size_t public_key_length = 0;

    if (psa_export_public_key(key_id,
                              public_key_der.data(),
                              public_key_der.size(),
                              &public_key_length) != PSA_SUCCESS) {
        psa_destroy_key(key_id);
        return std::unexpected(CryptoError("RSA public key export failed"));
    }
    public_key_der.resize(public_key_length);

    psa_destroy_key(key_id);

    return RsaKeyPair<KB>{
        .private_key_der = std::move(private_key_der),
        .public_key_der  = std::move(public_key_der),
    };
}
