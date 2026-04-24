/*
Copyright Permanence AI, 2026. All rights reserved.

*/

#pragma once

#include <cstddef>
#include <optional>
#include <stdexcept>

#include <psa/crypto.h>
#include <psa/crypto_values.h>

#include "secure_buffer.hpp"


[[nodiscard]]
inline auto derive_key(const std::size_t output_length,
                       const std::optional<SecureBuffer>& ikm  = std::nullopt,
                       const std::optional<SecureBuffer>& salt = std::nullopt,
                       const std::optional<SecureBuffer>& info = std::nullopt) -> SecureBuffer
{
    if (psa_crypto_init() != PSA_SUCCESS) {
        throw std::runtime_error("PSA crypto init failed");
    }

    // Generate IKM if not provided: twice the target key length per security convention
    SecureBuffer generated_ikm(0);
    if (!ikm.has_value()) {
        generated_ikm = SecureBuffer(output_length * 2);
        if (psa_generate_random(generated_ikm.data(), generated_ikm.size()) != PSA_SUCCESS) {
            throw std::runtime_error("IKM generation failed");
        }
    }
    const SecureBuffer& ikm_ref = ikm.has_value() ? *ikm : generated_ikm;

    psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attrs, PSA_KEY_TYPE_DERIVE);
    psa_set_key_bits(&attrs, static_cast<psa_key_bits_t>(ikm_ref.size() * 8));
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attrs, PSA_ALG_HKDF(PSA_ALG_SHA_384));

    mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
    if (psa_import_key(&attrs, ikm_ref.data(), ikm_ref.size(), &key_id) != PSA_SUCCESS) {
        throw std::runtime_error("IKM import failed");
    }

    psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;

    auto cleanup = [&]()
    {
        psa_key_derivation_abort(&op);
        psa_destroy_key(key_id);
    };

    if (psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_384)) != PSA_SUCCESS) {
        cleanup();
        throw std::runtime_error("HKDF setup failed");
    }

    if (salt.has_value()) {
        if (psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT,
                                           salt->data(), salt->size()) != PSA_SUCCESS) {
            cleanup();
            throw std::runtime_error("HKDF salt input failed");
        }
    }

    if (psa_key_derivation_input_key(&op, PSA_KEY_DERIVATION_INPUT_SECRET,
                                     key_id) != PSA_SUCCESS) {
        cleanup();
        throw std::runtime_error("HKDF secret input failed");
    }

    if (info.has_value()) {
        if (psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_INFO,
                                           info->data(), info->size()) != PSA_SUCCESS) {
            cleanup();
            throw std::runtime_error("HKDF info input failed");
        }
    } else {
        if (psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_INFO,
                                           nullptr, 0) != PSA_SUCCESS) {
            cleanup();
            throw std::runtime_error("HKDF info input failed");
        }
    }

    SecureBuffer output(output_length);
    if (psa_key_derivation_output_bytes(&op, output.data(), output.size()) != PSA_SUCCESS) {
        cleanup();
        throw std::runtime_error("HKDF output failed");
    }

    cleanup();
    return output;
}
