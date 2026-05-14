// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <new>

#include <psa/crypto.h>
#include <psa/crypto_sizes.h>
#include <psa/crypto_values.h>

#include "defs.hpp"
#include "ml_dsa_variant.hpp"
#include "ml_kem_variant.hpp"
#include "pqc_key_store.hpp"
#include "secure_buffer.hpp"
#include "sha_variant.hpp"
#include "slh_dsa_variant.hpp"

#ifdef SAFE_CRYPTO_PQC_LIBOQS
#include "liboqs_pqc.hpp"
#endif


// Wrapper around psa_key_attributes_t that carries PQC metadata for ML-DSA/ML-KEM
// keys.  Non-PQC paths pass .psa to all psa_* C functions unchanged.
struct PsaKeyAttributes {
    psa_key_attributes_t psa = PSA_KEY_ATTRIBUTES_INIT;
    psa_mbedtls::detail::PqcKeyType pqc_type{psa_mbedtls::detail::PqcKeyType::None};
    std::uint8_t pqc_variant{0};
};


// Production PSA/MbedTLS backend — every method is a direct forwarding call to
// the corresponding PSA C function or macro.  Tests substitute MockPsaBackend
// to exercise error branches without needing to induce real PSA failures.
struct RealPsaBackend {
    // Associated types — insulate callers from PSA/MbedTLS concrete type names.
    using Status        = psa_status_t;
    using KeyId         = mbedtls_svc_key_id_t;
    using Algorithm     = psa_algorithm_t;
    using KeyAttributes = PsaKeyAttributes;
    using KdfOperation  = psa_key_derivation_operation_t;
    using KdfStep       = psa_key_derivation_step_t;

    // Status sentinels — avoids PSA_SUCCESS / PSA_ERROR_* leaking into generic code.
    static constexpr Status ok              = PSA_SUCCESS;
    static constexpr Status err_invalid_sig = PSA_ERROR_INVALID_SIGNATURE;
    static constexpr Status err_invalid_arg = PSA_ERROR_INVALID_ARGUMENT;

    // Object factories for provider-specific init macros.
    [[nodiscard]]
    static KeyId null_key_id() noexcept {
        const KeyId k = MBEDTLS_SVC_KEY_ID_INIT;
        return k;
    }
    [[nodiscard]]
    static KeyAttributes make_key_attrs() noexcept {
        return {};
    }
    [[nodiscard]]
    static KdfOperation make_kdf_op() noexcept {
        KdfOperation o = PSA_KEY_DERIVATION_OPERATION_INIT;
        return o;
    }

    [[nodiscard]]
    static Status crypto_init() {
        return psa_crypto_init();
    }

    [[nodiscard]]
    static auto generate_random(const std::size_t output_size)
        -> std::expected<SecureBuffer, Status>
    {
        SecureBuffer output(output_size);
        const auto s = psa_generate_random(output.data(), output_size);
        if (s != PSA_SUCCESS) {
            return std::unexpected(s);
        }
        return output;
    }

    [[nodiscard]]
    static auto hash_compute(
        const Algorithm alg,
        const CryptoByte* input, const std::size_t input_length)
        -> std::expected<SecureBuffer, Status>
    {
        const std::size_t hash_size = PSA_HASH_MAX_SIZE;
        SecureBuffer hash(hash_size);
        std::size_t hash_length = 0;
        const auto s = psa_hash_compute(alg, input, input_length, hash.data(), hash_size, &hash_length);
        if (s != PSA_SUCCESS) {
            return std::unexpected(s);
        }
        hash.resize(hash_length);
        return hash;
    }

    [[nodiscard]]
    static auto import_key(
        const KeyAttributes* attributes,
        const CryptoByte* data, const std::size_t data_length)
        -> std::expected<KeyId, Status>
    {
#ifdef SAFE_CRYPTO_PQC_LIBOQS
        if (attributes != nullptr &&
            attributes->pqc_type != psa_mbedtls::detail::PqcKeyType::None) {
            using psa_mbedtls::detail::PqcKeyType;
            const bool is_private = (attributes->pqc_type == PqcKeyType::MlKemPrivate ||
                                     attributes->pqc_type == PqcKeyType::MlDsaPrivate);
            const CryptoByte* priv = is_private ? data : nullptr;
            const std::size_t priv_sz = is_private ? data_length : 0U;
            const CryptoByte* pub = is_private ? nullptr : data;
            const std::size_t pub_sz = is_private ? 0U : data_length;
            const unsigned int slot = psa_mbedtls::detail::pqc_key_store_import(
                attributes->pqc_type, attributes->pqc_variant, priv, priv_sz, pub, pub_sz);
            if (slot == 0U) { return std::unexpected(static_cast<Status>(PSA_ERROR_INVALID_ARGUMENT)); }
            return static_cast<KeyId>(slot);
        }
#endif
        KeyId key = null_key_id();
        const Status s = psa_import_key(attributes != nullptr ? &attributes->psa : nullptr,
                                        data, data_length, &key);
        if (s != PSA_SUCCESS) { return std::unexpected(s); }
        return key;
    }

    [[nodiscard]]
    static auto generate_key(
        const KeyAttributes* attributes)
        -> std::expected<KeyId, Status>
    {
#ifdef SAFE_CRYPTO_PQC_LIBOQS
        if (attributes != nullptr &&
            attributes->pqc_type != psa_mbedtls::detail::PqcKeyType::None) {
            using psa_mbedtls::detail::PqcKeyType;
            if (attributes->pqc_type == PqcKeyType::MlKemPrivate) {
                const auto v = static_cast<MlKemVariant>(attributes->pqc_variant);
                const std::size_t pub_sz  = ml_kem_public_key_size(v);
                const std::size_t priv_sz = ml_kem_private_key_size(v);
                auto* pub_buf  = new (std::nothrow) CryptoByte[pub_sz];   // NOLINT(cppcoreguidelines-owning-memory)
                auto* priv_buf = new (std::nothrow) CryptoByte[priv_sz];  // NOLINT(cppcoreguidelines-owning-memory)
                if (pub_buf == nullptr || priv_buf == nullptr) {
                    delete[] pub_buf;   // NOLINT(cppcoreguidelines-owning-memory)
                    delete[] priv_buf;  // NOLINT(cppcoreguidelines-owning-memory)
                    return std::unexpected(static_cast<Status>(PSA_ERROR_INVALID_ARGUMENT));
                }
                const bool ok_kg = liboqs_pqc::ml_kem_keygen(v, pub_buf, pub_sz, priv_buf, priv_sz);
                if (!ok_kg) {
                    ::detail::secure_zero(pub_buf,  pub_sz);
                    ::detail::secure_zero(priv_buf, priv_sz);
                    delete[] pub_buf;   // NOLINT(cppcoreguidelines-owning-memory)
                    delete[] priv_buf;  // NOLINT(cppcoreguidelines-owning-memory)
                    return std::unexpected(static_cast<Status>(PSA_ERROR_INVALID_ARGUMENT));
                }
                const unsigned int slot = psa_mbedtls::detail::pqc_key_store_import(
                    PqcKeyType::MlKemPrivate, attributes->pqc_variant,
                    priv_buf, priv_sz, pub_buf, pub_sz);
                ::detail::secure_zero(priv_buf, priv_sz);
                ::detail::secure_zero(pub_buf,  pub_sz);
                delete[] priv_buf;  // NOLINT(cppcoreguidelines-owning-memory)
                delete[] pub_buf;   // NOLINT(cppcoreguidelines-owning-memory)
                if (slot == 0U) { return std::unexpected(static_cast<Status>(PSA_ERROR_INVALID_ARGUMENT)); }
                return static_cast<KeyId>(slot);
            }
            if (attributes->pqc_type == PqcKeyType::MlDsaPrivate) {
                const auto v = static_cast<MlDsaVariant>(attributes->pqc_variant);
                const std::size_t pub_sz  = ml_dsa_public_key_size(v);
                const std::size_t priv_sz = ml_dsa_private_key_size(v);
                auto* pub_buf  = new (std::nothrow) CryptoByte[pub_sz];   // NOLINT(cppcoreguidelines-owning-memory)
                auto* priv_buf = new (std::nothrow) CryptoByte[priv_sz];  // NOLINT(cppcoreguidelines-owning-memory)
                if (pub_buf == nullptr || priv_buf == nullptr) {
                    delete[] pub_buf;   // NOLINT(cppcoreguidelines-owning-memory)
                    delete[] priv_buf;  // NOLINT(cppcoreguidelines-owning-memory)
                    return std::unexpected(static_cast<Status>(PSA_ERROR_INVALID_ARGUMENT));
                }
                const bool ok_kg = liboqs_pqc::ml_dsa_keygen(v, pub_buf, pub_sz, priv_buf, priv_sz);
                if (!ok_kg) {
                    ::detail::secure_zero(pub_buf,  pub_sz);
                    ::detail::secure_zero(priv_buf, priv_sz);
                    delete[] pub_buf;   // NOLINT(cppcoreguidelines-owning-memory)
                    delete[] priv_buf;  // NOLINT(cppcoreguidelines-owning-memory)
                    return std::unexpected(static_cast<Status>(PSA_ERROR_INVALID_ARGUMENT));
                }
                const unsigned int slot = psa_mbedtls::detail::pqc_key_store_import(
                    PqcKeyType::MlDsaPrivate, attributes->pqc_variant,
                    priv_buf, priv_sz, pub_buf, pub_sz);
                ::detail::secure_zero(priv_buf, priv_sz);
                ::detail::secure_zero(pub_buf,  pub_sz);
                delete[] priv_buf;  // NOLINT(cppcoreguidelines-owning-memory)
                delete[] pub_buf;   // NOLINT(cppcoreguidelines-owning-memory)
                if (slot == 0U) { return std::unexpected(static_cast<Status>(PSA_ERROR_INVALID_ARGUMENT)); }
                return static_cast<KeyId>(slot);
            }
            return std::unexpected(static_cast<Status>(PSA_ERROR_INVALID_ARGUMENT));
        }
#endif
        KeyId key = null_key_id();
        const Status s = psa_generate_key(attributes != nullptr ? &attributes->psa : nullptr, &key);
        if (s != PSA_SUCCESS) { return std::unexpected(s); }
        return key;
    }

    [[nodiscard]]
    static Status destroy_key(const KeyId key) {
#ifdef SAFE_CRYPTO_PQC_LIBOQS
        if (psa_mbedtls::detail::pqc_key_id_is_pqc(static_cast<unsigned int>(key))) {
            psa_mbedtls::detail::pqc_key_store_destroy(static_cast<unsigned int>(key));
            return PSA_SUCCESS;
        }
#endif
        return psa_destroy_key(key);
    }

    [[nodiscard]]
    static Status export_key(
        const KeyId key,
        CryptoByte* data, const std::size_t data_size, std::size_t* data_length)
    {
#ifdef SAFE_CRYPTO_PQC_LIBOQS
        if (psa_mbedtls::detail::pqc_key_id_is_pqc(static_cast<unsigned int>(key))) {
            const auto kv = psa_mbedtls::detail::pqc_key_store_get_private(static_cast<unsigned int>(key));
            if (!kv) { return PSA_ERROR_INVALID_ARGUMENT; }
            if (data_size < kv->data.size()) { return PSA_ERROR_BUFFER_TOO_SMALL; }
            std::memcpy(data, kv->data.data(), kv->data.size());
            *data_length = kv->data.size();
            return PSA_SUCCESS;
        }
#endif
        return psa_export_key(key, data, data_size, data_length);
    }

    [[nodiscard]]
    static Status export_public_key(
        const KeyId key,
        CryptoByte* data, const std::size_t data_size, std::size_t* data_length)
    {
#ifdef SAFE_CRYPTO_PQC_LIBOQS
        if (psa_mbedtls::detail::pqc_key_id_is_pqc(static_cast<unsigned int>(key))) {
            const auto kv = psa_mbedtls::detail::pqc_key_store_get_public(static_cast<unsigned int>(key));
            if (!kv) { return PSA_ERROR_INVALID_ARGUMENT; }
            if (data_size < kv->data.size()) { return PSA_ERROR_BUFFER_TOO_SMALL; }
            std::memcpy(data, kv->data.data(), kv->data.size());
            *data_length = kv->data.size();
            return PSA_SUCCESS;
        }
#endif
        return psa_export_public_key(key, data, data_size, data_length);
    }

    [[nodiscard]]
    static auto mac_compute(  // NOLINT(readability-function-size)
        const KeyId key, const Algorithm alg,
        const CryptoByte* input, const std::size_t input_length)
        -> std::expected<SecureBuffer, Status>
    {
        const std::size_t mac_size = PSA_MAC_MAX_SIZE;
        SecureBuffer mac(mac_size);
        std::size_t mac_length = 0;
        const auto s = psa_mac_compute(key, alg, input, input_length, mac.data(), mac_size, &mac_length);
        if (s != PSA_SUCCESS) {
            return std::unexpected(s);
        }
        mac.resize(mac_length);
        return mac;
    }

    [[nodiscard]]
    static Status mac_verify(
        const KeyId key, const Algorithm alg,
        const CryptoByte* input, const std::size_t input_length,
        const CryptoByte* mac, const std::size_t mac_length)
    {
        return psa_mac_verify(key, alg, input, input_length, mac, mac_length);
    }

    [[nodiscard]]
    static Status aead_encrypt(  // NOLINT(readability-function-size)
        const KeyId key, const Algorithm alg,
        const CryptoByte* nonce, const std::size_t nonce_length,
        const CryptoByte* additional_data, const std::size_t additional_data_length,
        const CryptoByte* plaintext, const std::size_t plaintext_length,
        CryptoByte* ciphertext, const std::size_t ciphertext_size,
        std::size_t* ciphertext_length)
    {
        return psa_aead_encrypt(
            key, alg,
            nonce, nonce_length,
            additional_data, additional_data_length,
            plaintext, plaintext_length,
            ciphertext, ciphertext_size, ciphertext_length);
    }

    [[nodiscard]]
    static Status aead_decrypt(  // NOLINT(readability-function-size)
        const KeyId key, const Algorithm alg,
        const CryptoByte* nonce, const std::size_t nonce_length,
        const CryptoByte* additional_data, const std::size_t additional_data_length,
        const CryptoByte* ciphertext, const std::size_t ciphertext_length,
        CryptoByte* plaintext, const std::size_t plaintext_size,
        std::size_t* plaintext_length)
    {
        return psa_aead_decrypt(
            key, alg,
            nonce, nonce_length,
            additional_data, additional_data_length,
            ciphertext, ciphertext_length,
            plaintext, plaintext_size, plaintext_length);
    }

    [[nodiscard]]
    static auto sign_message(  // NOLINT(readability-function-size)
        const KeyId key, const Algorithm alg,
        const CryptoByte* input, const std::size_t input_length)
        -> std::expected<SecureBuffer, Status>
    {
        const std::size_t sig_max = PSA_SIGNATURE_MAX_SIZE;
        SecureBuffer signature(sig_max);
        std::size_t sig_len = 0;
#ifdef SAFE_CRYPTO_PQC_LIBOQS
        if ((alg & kPqcAlgCategoryMask) == kAlgMlDsaBase) {
            using psa_mbedtls::detail::PqcKeyType;
            if (!psa_mbedtls::detail::pqc_key_id_is_pqc(static_cast<unsigned int>(key))) {
                return std::unexpected(static_cast<Status>(PSA_ERROR_INVALID_ARGUMENT));
            }
            const auto kv_sign = psa_mbedtls::detail::pqc_key_store_get_private(static_cast<unsigned int>(key));
            if (!kv_sign || kv_sign->type != PqcKeyType::MlDsaPrivate) {
                return std::unexpected(static_cast<Status>(PSA_ERROR_INVALID_ARGUMENT));
            }
            const auto v = static_cast<MlDsaVariant>(kv_sign->variant);
            if (alg != alg_ml_dsa(v)) {
                return std::unexpected(static_cast<Status>(PSA_ERROR_INVALID_ARGUMENT));
            }
            const std::size_t exact_size = ml_dsa_signature_size(v);
            if (!liboqs_pqc::ml_dsa_sign(v, kv_sign->data.data(), kv_sign->data.size(),
                                          input, input_length,
                                          signature.data(), exact_size, &sig_len)) {
                return std::unexpected(static_cast<Status>(PSA_ERROR_INVALID_ARGUMENT));
            }
            signature.resize(sig_len);
            return signature;
        }
#endif
        const auto s = psa_sign_message(key, alg, input, input_length,
                                         signature.data(), sig_max, &sig_len);
        if (s != PSA_SUCCESS) {
            return std::unexpected(s);
        }
        signature.resize(sig_len);
        return signature;
    }

    [[nodiscard]]
    static Status verify_message(
        const KeyId key, const Algorithm alg,
        const CryptoByte* input, const std::size_t input_length,
        const CryptoByte* signature, const std::size_t signature_length)
    {
#ifdef SAFE_CRYPTO_PQC_LIBOQS
        if ((alg & kPqcAlgCategoryMask) == kAlgMlDsaBase) {
            using psa_mbedtls::detail::PqcKeyType;
            if (!psa_mbedtls::detail::pqc_key_id_is_pqc(static_cast<unsigned int>(key))) {
                return PSA_ERROR_INVALID_ARGUMENT;
            }
            const auto kv_ver = psa_mbedtls::detail::pqc_key_store_get_public(static_cast<unsigned int>(key));
            if (!kv_ver || (kv_ver->type != PqcKeyType::MlDsaPublic && kv_ver->type != PqcKeyType::MlDsaPrivate)) {
                return PSA_ERROR_INVALID_ARGUMENT;
            }
            const auto v = static_cast<MlDsaVariant>(kv_ver->variant);
            if (alg != alg_ml_dsa(v)) { return PSA_ERROR_INVALID_ARGUMENT; }
            return liboqs_pqc::ml_dsa_verify(v, kv_ver->data.data(), kv_ver->data.size(),
                                              input, input_length,
                                              signature, signature_length)
                ? PSA_SUCCESS : PSA_ERROR_INVALID_SIGNATURE;
        }
#endif
        return psa_verify_message(
            key, alg, input, input_length, signature, signature_length);
    }

    [[nodiscard]]
    static Status raw_key_agreement(  // NOLINT(readability-function-size)
        const Algorithm alg,
        const KeyId private_key,
        const CryptoByte* peer_key, const std::size_t peer_key_length,
        CryptoByte* output, const std::size_t output_size,
        std::size_t* output_length)
    {
        return psa_raw_key_agreement(
            alg, private_key, peer_key, peer_key_length,
            output, output_size, output_length);
    }

    [[nodiscard]]
    static Status asymmetric_encrypt(  // NOLINT(readability-function-size)
        const KeyId key, const Algorithm alg,
        const CryptoByte* input, const std::size_t input_length,
        const CryptoByte* salt, const std::size_t salt_length,
        CryptoByte* output, const std::size_t output_size,
        std::size_t* output_length)
    {
        return psa_asymmetric_encrypt(
            key, alg, input, input_length, salt, salt_length,
            output, output_size, output_length);
    }

    [[nodiscard]]
    static Status asymmetric_decrypt(  // NOLINT(readability-function-size)
        const KeyId key, const Algorithm alg,
        const CryptoByte* input, const std::size_t input_length,
        const CryptoByte* salt, const std::size_t salt_length,
        CryptoByte* output, const std::size_t output_size,
        std::size_t* output_length)
    {
        return psa_asymmetric_decrypt(
            key, alg, input, input_length, salt, salt_length,
            output, output_size, output_length);
    }

    [[nodiscard]]
    static Status key_derivation_setup(
        KdfOperation* operation, const Algorithm alg)
    {
        return psa_key_derivation_setup(operation, alg);
    }

    [[nodiscard]]
    static Status key_derivation_input_key(
        KdfOperation* operation,
        const KdfStep step,
        const KeyId key)
    {
        return psa_key_derivation_input_key(operation, step, key);
    }

    [[nodiscard]]
    static Status key_derivation_input_bytes(
        KdfOperation* operation,
        const KdfStep step,
        const CryptoByte* data, const std::size_t data_length)
    {
        return psa_key_derivation_input_bytes(operation, step, data, data_length);
    }

    [[nodiscard]]
    static Status key_derivation_output_bytes(
        KdfOperation* operation,
        CryptoByte* output, const std::size_t output_length)
    {
        return psa_key_derivation_output_bytes(operation, output, output_length);
    }

    [[nodiscard]]
    static Status key_derivation_abort(KdfOperation* operation) {
        return psa_key_derivation_abort(operation);
    }

    // -------------------------------------------------------------------------
    // Algorithm constants — provider-native algorithm selectors.
    // -------------------------------------------------------------------------
    [[nodiscard]]
    static Algorithm alg_sha(const ShaVariant v) noexcept {
        switch (v) {
            case ShaVariant::Sha256:   return PSA_ALG_SHA_256;
            case ShaVariant::Sha384:   return PSA_ALG_SHA_384;
            case ShaVariant::Sha512:   return PSA_ALG_SHA_512;
            case ShaVariant::Sha3_256: return PSA_ALG_SHA3_256;
            case ShaVariant::Sha3_384: return PSA_ALG_SHA3_384;
            case ShaVariant::Sha3_512: return PSA_ALG_SHA3_512;
        }
    }
    [[nodiscard]]
    static Algorithm alg_hmac(const ShaVariant v) noexcept {
        return PSA_ALG_HMAC(alg_sha(v));
    }
    [[nodiscard]]
    static constexpr Algorithm alg_ecdsa()              noexcept { return PSA_ALG_ECDSA(PSA_ALG_SHA_384); }
    [[nodiscard]]
    static constexpr Algorithm alg_ecdh()               noexcept { return PSA_ALG_ECDH; }
    [[nodiscard]]
    static constexpr Algorithm alg_hkdf()               noexcept { return PSA_ALG_HKDF(PSA_ALG_SHA_384); }
    [[nodiscard]]
    static constexpr Algorithm alg_hkdf_expand()        noexcept { return PSA_ALG_HKDF_EXPAND(PSA_ALG_SHA_384); }
    [[nodiscard]]
    static constexpr Algorithm alg_aes_gcm()            noexcept { return PSA_ALG_GCM; }
    [[nodiscard]]
    static constexpr Algorithm alg_chacha20_poly1305()  noexcept { return PSA_ALG_CHACHA20_POLY1305; }
    [[nodiscard]]
    static constexpr Algorithm alg_rsa_oaep()           noexcept { return PSA_ALG_RSA_OAEP(PSA_ALG_SHA_384); }
    [[nodiscard]]
    static constexpr Algorithm alg_rsa_pss()            noexcept { return PSA_ALG_RSA_PSS(PSA_ALG_SHA_384); }

    // -------------------------------------------------------------------------
    // KDF step constants.
    // -------------------------------------------------------------------------
    [[nodiscard]]
    static constexpr KdfStep kdf_step_secret() noexcept { return PSA_KEY_DERIVATION_INPUT_SECRET; }
    [[nodiscard]]
    static constexpr KdfStep kdf_step_salt()   noexcept { return PSA_KEY_DERIVATION_INPUT_SALT;   }
    [[nodiscard]]
    static constexpr KdfStep kdf_step_info()   noexcept { return PSA_KEY_DERIVATION_INPUT_INFO;   }

    // -------------------------------------------------------------------------
    // Key attribute factories.
    // -------------------------------------------------------------------------
    [[nodiscard]]
    static KeyAttributes make_hkdf_derive_attrs(const std::size_t key_size_bits) noexcept {
        KeyAttributes a{};
        psa_set_key_type(&a.psa, PSA_KEY_TYPE_DERIVE);
        psa_set_key_bits(&a.psa, static_cast<psa_key_bits_t>(key_size_bits));
        psa_set_key_usage_flags(&a.psa, PSA_KEY_USAGE_DERIVE);
        psa_set_key_algorithm(&a.psa, alg_hkdf());
        return a;
    }
    [[nodiscard]]
    static KeyAttributes make_hkdf_expand_derive_attrs(const std::size_t key_size_bits) noexcept {
        KeyAttributes a{};
        psa_set_key_type(&a.psa, PSA_KEY_TYPE_DERIVE);
        psa_set_key_bits(&a.psa, static_cast<psa_key_bits_t>(key_size_bits));
        psa_set_key_usage_flags(&a.psa, PSA_KEY_USAGE_DERIVE);
        psa_set_key_algorithm(&a.psa, alg_hkdf_expand());
        return a;
    }
    [[nodiscard]]
    static KeyAttributes make_hmac_generate_attrs(const ShaVariant v,
                                                  const std::size_t key_size_bits) noexcept {
        KeyAttributes a{};
        psa_set_key_type(&a.psa, PSA_KEY_TYPE_HMAC);
        psa_set_key_bits(&a.psa, static_cast<psa_key_bits_t>(key_size_bits));
        psa_set_key_usage_flags(&a.psa, PSA_KEY_USAGE_SIGN_MESSAGE);
        psa_set_key_algorithm(&a.psa, alg_hmac(v));
        return a;
    }
    [[nodiscard]]
    static KeyAttributes make_hmac_verify_attrs(const ShaVariant v,
                                                const std::size_t key_size_bits) noexcept {
        KeyAttributes a{};
        psa_set_key_type(&a.psa, PSA_KEY_TYPE_HMAC);
        psa_set_key_bits(&a.psa, static_cast<psa_key_bits_t>(key_size_bits));
        psa_set_key_usage_flags(&a.psa, PSA_KEY_USAGE_VERIFY_MESSAGE);
        psa_set_key_algorithm(&a.psa, alg_hmac(v));
        return a;
    }
    [[nodiscard]]
    static KeyAttributes make_ecdsa_generate_attrs(const std::size_t key_bits) noexcept {
        KeyAttributes a{};
        psa_set_key_type(&a.psa, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
        psa_set_key_bits(&a.psa, static_cast<psa_key_bits_t>(key_bits));
        psa_set_key_usage_flags(&a.psa, PSA_KEY_USAGE_SIGN_MESSAGE |
                                    PSA_KEY_USAGE_VERIFY_MESSAGE |
                                    PSA_KEY_USAGE_EXPORT);
        psa_set_key_algorithm(&a.psa, alg_ecdsa());
        return a;
    }
    [[nodiscard]]
    static KeyAttributes make_ecdsa_sign_attrs(const std::size_t key_bits) noexcept {
        KeyAttributes a{};
        psa_set_key_type(&a.psa, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
        psa_set_key_bits(&a.psa, static_cast<psa_key_bits_t>(key_bits));
        psa_set_key_usage_flags(&a.psa, PSA_KEY_USAGE_SIGN_MESSAGE);
        psa_set_key_algorithm(&a.psa, alg_ecdsa());
        return a;
    }
    [[nodiscard]]
    static KeyAttributes make_ecdsa_verify_attrs(const std::size_t key_bits) noexcept {
        KeyAttributes a{};
        psa_set_key_type(&a.psa, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
        psa_set_key_bits(&a.psa, static_cast<psa_key_bits_t>(key_bits));
        psa_set_key_usage_flags(&a.psa, PSA_KEY_USAGE_VERIFY_MESSAGE);
        psa_set_key_algorithm(&a.psa, alg_ecdsa());
        return a;
    }
    [[nodiscard]]
    static KeyAttributes make_ecdh_generate_attrs(const std::size_t key_bits) noexcept {
        KeyAttributes a{};
        psa_set_key_type(&a.psa, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
        psa_set_key_bits(&a.psa, static_cast<psa_key_bits_t>(key_bits));
        psa_set_key_usage_flags(&a.psa, PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
        psa_set_key_algorithm(&a.psa, alg_ecdh());
        return a;
    }
    [[nodiscard]]
    static KeyAttributes make_ecdh_agree_attrs(const std::size_t key_bits) noexcept {
        KeyAttributes a{};
        psa_set_key_type(&a.psa, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
        psa_set_key_bits(&a.psa, static_cast<psa_key_bits_t>(key_bits));
        psa_set_key_usage_flags(&a.psa, PSA_KEY_USAGE_DERIVE);
        psa_set_key_algorithm(&a.psa, alg_ecdh());
        return a;
    }
    [[nodiscard]]
    static KeyAttributes make_aes256_gcm_encrypt_attrs() noexcept {
        KeyAttributes a{};
        psa_set_key_type(&a.psa, PSA_KEY_TYPE_AES);
        psa_set_key_bits(&a.psa, static_cast<psa_key_bits_t>(aes256_key_bits));
        psa_set_key_usage_flags(&a.psa, PSA_KEY_USAGE_ENCRYPT);
        psa_set_key_algorithm(&a.psa, alg_aes_gcm());
        return a;
    }
    [[nodiscard]]
    static KeyAttributes make_aes256_gcm_decrypt_attrs() noexcept {
        KeyAttributes a{};
        psa_set_key_type(&a.psa, PSA_KEY_TYPE_AES);
        psa_set_key_bits(&a.psa, static_cast<psa_key_bits_t>(aes256_key_bits));
        psa_set_key_usage_flags(&a.psa, PSA_KEY_USAGE_DECRYPT);
        psa_set_key_algorithm(&a.psa, alg_aes_gcm());
        return a;
    }
    [[nodiscard]]
    static KeyAttributes make_chacha20_poly1305_encrypt_attrs() noexcept {
        KeyAttributes a{};
        psa_set_key_type(&a.psa, PSA_KEY_TYPE_CHACHA20);
        psa_set_key_bits(&a.psa, static_cast<psa_key_bits_t>(chacha20_key_bits));
        psa_set_key_usage_flags(&a.psa, PSA_KEY_USAGE_ENCRYPT);
        psa_set_key_algorithm(&a.psa, alg_chacha20_poly1305());
        return a;
    }
    [[nodiscard]]
    static KeyAttributes make_chacha20_poly1305_decrypt_attrs() noexcept {
        KeyAttributes a{};
        psa_set_key_type(&a.psa, PSA_KEY_TYPE_CHACHA20);
        psa_set_key_bits(&a.psa, static_cast<psa_key_bits_t>(chacha20_key_bits));
        psa_set_key_usage_flags(&a.psa, PSA_KEY_USAGE_DECRYPT);
        psa_set_key_algorithm(&a.psa, alg_chacha20_poly1305());
        return a;
    }
    [[nodiscard]]
    static KeyAttributes make_rsa_oaep_encrypt_attrs(const std::size_t key_bits) noexcept {
        KeyAttributes a{};
        psa_set_key_type(&a.psa, PSA_KEY_TYPE_RSA_PUBLIC_KEY);
        psa_set_key_bits(&a.psa, static_cast<psa_key_bits_t>(key_bits));
        psa_set_key_usage_flags(&a.psa, PSA_KEY_USAGE_ENCRYPT);
        psa_set_key_algorithm(&a.psa, alg_rsa_oaep());
        return a;
    }
    [[nodiscard]]
    static KeyAttributes make_rsa_oaep_decrypt_attrs(const std::size_t key_bits) noexcept {
        KeyAttributes a{};
        psa_set_key_type(&a.psa, PSA_KEY_TYPE_RSA_KEY_PAIR);
        psa_set_key_bits(&a.psa, static_cast<psa_key_bits_t>(key_bits));
        psa_set_key_usage_flags(&a.psa, PSA_KEY_USAGE_DECRYPT);
        psa_set_key_algorithm(&a.psa, alg_rsa_oaep());
        return a;
    }
    [[nodiscard]]
    static KeyAttributes make_rsa_pss_sign_attrs(const std::size_t key_bits) noexcept {
        KeyAttributes a{};
        psa_set_key_type(&a.psa, PSA_KEY_TYPE_RSA_KEY_PAIR);
        psa_set_key_bits(&a.psa, static_cast<psa_key_bits_t>(key_bits));
        psa_set_key_usage_flags(&a.psa, PSA_KEY_USAGE_SIGN_MESSAGE);
        psa_set_key_algorithm(&a.psa, alg_rsa_pss());
        return a;
    }
    [[nodiscard]]
    static KeyAttributes make_rsa_pss_verify_attrs(const std::size_t key_bits) noexcept {
        KeyAttributes a{};
        psa_set_key_type(&a.psa, PSA_KEY_TYPE_RSA_PUBLIC_KEY);
        psa_set_key_bits(&a.psa, static_cast<psa_key_bits_t>(key_bits));
        psa_set_key_usage_flags(&a.psa, PSA_KEY_USAGE_VERIFY_MESSAGE);
        psa_set_key_algorithm(&a.psa, alg_rsa_pss());
        return a;
    }
    [[nodiscard]]
    static KeyAttributes make_rsa_key_pair_attrs(const std::size_t key_bits) noexcept {
        KeyAttributes a{};
        psa_set_key_type(&a.psa, PSA_KEY_TYPE_RSA_KEY_PAIR);
        psa_set_key_bits(&a.psa, static_cast<psa_key_bits_t>(key_bits));
        psa_set_key_usage_flags(&a.psa, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT |
                                    PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE |
                                    PSA_KEY_USAGE_EXPORT);
        psa_set_key_algorithm(&a.psa, alg_rsa_oaep());
        return a;
    }

    // -------------------------------------------------------------------------
    // Output size helpers — abstract PSA_*_OUTPUT_SIZE macros.
    // -------------------------------------------------------------------------
    [[nodiscard]]
    static std::size_t ecdsa_sign_output_size(const std::size_t key_bits) noexcept {
        return PSA_SIGN_OUTPUT_SIZE(
            PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1),
            static_cast<psa_key_bits_t>(key_bits),
            alg_ecdsa());
    }
    [[nodiscard]]
    static std::size_t ecdh_shared_secret_size(const std::size_t key_bits) noexcept {
        return PSA_RAW_KEY_AGREEMENT_OUTPUT_SIZE(
            PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1),
            static_cast<psa_key_bits_t>(key_bits));
    }
    [[nodiscard]]
    static std::size_t ec_private_key_export_size(const std::size_t key_bits) noexcept {
        return PSA_EXPORT_KEY_OUTPUT_SIZE(
            PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1),
            static_cast<psa_key_bits_t>(key_bits));
    }
    [[nodiscard]]
    static std::size_t ec_public_key_export_size(const std::size_t key_bits) noexcept {
        return PSA_EXPORT_PUBLIC_KEY_OUTPUT_SIZE(
            PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1),
            static_cast<psa_key_bits_t>(key_bits));
    }
    [[nodiscard]]
    static std::size_t aes_gcm_encrypt_output_size(const std::size_t plaintext_size) noexcept {
        return PSA_AEAD_ENCRYPT_OUTPUT_SIZE(PSA_KEY_TYPE_AES, PSA_ALG_GCM, plaintext_size);
    }
    [[nodiscard]]
    static std::size_t aes_gcm_decrypt_output_size(const std::size_t ciphertext_size) noexcept {
        return PSA_AEAD_DECRYPT_OUTPUT_SIZE(PSA_KEY_TYPE_AES, PSA_ALG_GCM, ciphertext_size);
    }
    [[nodiscard]]
    static std::size_t chacha20_encrypt_output_size(const std::size_t plaintext_size) noexcept {
        return PSA_AEAD_ENCRYPT_OUTPUT_SIZE(
            PSA_KEY_TYPE_CHACHA20, PSA_ALG_CHACHA20_POLY1305, plaintext_size);
    }
    [[nodiscard]]
    static std::size_t chacha20_decrypt_output_size(const std::size_t ciphertext_size) noexcept {
        return PSA_AEAD_DECRYPT_OUTPUT_SIZE(
            PSA_KEY_TYPE_CHACHA20, PSA_ALG_CHACHA20_POLY1305, ciphertext_size);
    }
    [[nodiscard]]
    static std::size_t rsa_oaep_encrypt_output_size(const std::size_t key_bits) noexcept {
        return PSA_ASYMMETRIC_ENCRYPT_OUTPUT_SIZE(
            PSA_KEY_TYPE_RSA_PUBLIC_KEY,
            static_cast<psa_key_bits_t>(key_bits),
            alg_rsa_oaep());
    }
    [[nodiscard]]
    static std::size_t rsa_oaep_decrypt_output_size(const std::size_t key_bits) noexcept { // NOLINT(readability-function-size,readability-function-cognitive-complexity)
        return PSA_ASYMMETRIC_DECRYPT_OUTPUT_SIZE(
            PSA_KEY_TYPE_RSA_KEY_PAIR,
            static_cast<psa_key_bits_t>(key_bits),
            alg_rsa_oaep());
    }
    [[nodiscard]]
    static std::size_t rsa_pss_sign_output_size(const std::size_t key_bits) noexcept {
        return PSA_SIGN_OUTPUT_SIZE(
            PSA_KEY_TYPE_RSA_KEY_PAIR,
            static_cast<psa_key_bits_t>(key_bits),
            alg_rsa_pss());
    }
    [[nodiscard]]
    static std::size_t rsa_private_key_export_size(const std::size_t key_bits) noexcept {
        return PSA_EXPORT_KEY_OUTPUT_SIZE(
            PSA_KEY_TYPE_RSA_KEY_PAIR,
            static_cast<psa_key_bits_t>(key_bits));
    }
    [[nodiscard]]
    static std::size_t rsa_public_key_export_size(const std::size_t key_bits) noexcept {
        return PSA_EXPORT_PUBLIC_KEY_OUTPUT_SIZE(
            PSA_KEY_TYPE_RSA_KEY_PAIR,
            static_cast<psa_key_bits_t>(key_bits));
    }

    // SLH-DSA — not supported by MbedTLS 4.1; all operations return err_invalid_arg.
    [[nodiscard]]
    static Algorithm alg_slh_dsa(const SlhDsaVariant /*v*/) noexcept {
        return static_cast<Algorithm>(0);  // PSA_ALG_NONE — unsupported
    }
    [[nodiscard]]
    static KeyAttributes make_slh_dsa_sign_attrs(const SlhDsaVariant /*v*/) noexcept {
        return {};
    }
    [[nodiscard]]
    static KeyAttributes make_slh_dsa_verify_attrs(const SlhDsaVariant /*v*/) noexcept {
        return {};
    }
    [[nodiscard]]
    static KeyAttributes make_slh_dsa_generate_attrs(const SlhDsaVariant /*v*/) noexcept {
        return {};
    }
    [[nodiscard]]
    static std::size_t slh_dsa_sign_output_size(const SlhDsaVariant v) noexcept {
        return slh_dsa_signature_size(v);
    }
    [[nodiscard]]
    static std::size_t slh_dsa_private_key_export_size(const SlhDsaVariant v) noexcept {
        return slh_dsa_private_key_size(v);
    }
    [[nodiscard]]
    static std::size_t slh_dsa_public_key_export_size(const SlhDsaVariant v) noexcept {
        return slh_dsa_public_key_size(v);
    }

    // PQC algorithm base tags (liboqs-routed; top byte = category, low byte = variant).
    static constexpr Algorithm kAlgMlDsaBase = 0xE100U;
    static constexpr Algorithm kAlgMlKemBase = 0xE200U;
    // Mask to extract the category portion of a PQC algorithm tag.
    static constexpr Algorithm kPqcAlgCategoryMask = 0xFF00U;

    // ML-DSA — not supported by native MbedTLS 4.1; routed via liboqs when available.
    [[nodiscard]]
    static Algorithm alg_ml_dsa(const MlDsaVariant v) noexcept {
        // Encode variant in low byte so sign/verify can dispatch without key ID.
        return kAlgMlDsaBase | static_cast<Algorithm>(v);
    }
    [[nodiscard]]
    static KeyAttributes make_ml_dsa_sign_attrs(const MlDsaVariant v) noexcept {
#ifdef SAFE_CRYPTO_PQC_LIBOQS
        PsaKeyAttributes a{};
        a.pqc_type    = psa_mbedtls::detail::PqcKeyType::MlDsaPrivate;
        a.pqc_variant = static_cast<std::uint8_t>(v);
        return a;
#else
        (void)v; return {};
#endif
    }
    [[nodiscard]]
    static KeyAttributes make_ml_dsa_verify_attrs(const MlDsaVariant v) noexcept {
#ifdef SAFE_CRYPTO_PQC_LIBOQS
        PsaKeyAttributes a{};
        a.pqc_type    = psa_mbedtls::detail::PqcKeyType::MlDsaPublic;
        a.pqc_variant = static_cast<std::uint8_t>(v);
        return a;
#else
        (void)v; return {};
#endif
    }
    [[nodiscard]]
    static KeyAttributes make_ml_dsa_generate_attrs(const MlDsaVariant v) noexcept {
#ifdef SAFE_CRYPTO_PQC_LIBOQS
        PsaKeyAttributes a{};
        a.pqc_type    = psa_mbedtls::detail::PqcKeyType::MlDsaPrivate;
        a.pqc_variant = static_cast<std::uint8_t>(v);
        return a;
#else
        (void)v; return {};
#endif
    }
    [[nodiscard]]
    static std::size_t ml_dsa_sign_output_size(const MlDsaVariant v) noexcept {
        return ml_dsa_signature_size(v);
    }
    [[nodiscard]]
    static std::size_t ml_dsa_private_key_export_size(const MlDsaVariant v) noexcept {
        return ml_dsa_private_key_size(v);
    }
    [[nodiscard]]
    static std::size_t ml_dsa_public_key_export_size(const MlDsaVariant v) noexcept {
        return ml_dsa_public_key_size(v);
    }

    // ML-KEM — not supported by native MbedTLS 4.1; routed via liboqs when available.
    [[nodiscard]]
    static Algorithm alg_ml_kem(const MlKemVariant v) noexcept {
        return kAlgMlKemBase | static_cast<Algorithm>(v);
    }
    [[nodiscard]]
    static KeyAttributes make_ml_kem_generate_attrs(const MlKemVariant v) noexcept {
#ifdef SAFE_CRYPTO_PQC_LIBOQS
        PsaKeyAttributes a{};
        a.pqc_type    = psa_mbedtls::detail::PqcKeyType::MlKemPrivate;
        a.pqc_variant = static_cast<std::uint8_t>(v);
        return a;
#else
        (void)v; return {};
#endif
    }
    [[nodiscard]]
    static KeyAttributes make_ml_kem_encap_attrs(const MlKemVariant v) noexcept {
#ifdef SAFE_CRYPTO_PQC_LIBOQS
        PsaKeyAttributes a{};
        a.pqc_type    = psa_mbedtls::detail::PqcKeyType::MlKemPublic;
        a.pqc_variant = static_cast<std::uint8_t>(v);
        return a;
#else
        (void)v; return {};
#endif
    }
    [[nodiscard]]
    static KeyAttributes make_ml_kem_decap_attrs(const MlKemVariant v) noexcept {
#ifdef SAFE_CRYPTO_PQC_LIBOQS
        PsaKeyAttributes a{};
        a.pqc_type    = psa_mbedtls::detail::PqcKeyType::MlKemPrivate;
        a.pqc_variant = static_cast<std::uint8_t>(v);
        return a;
#else
        (void)v; return {};
#endif
    }
    [[nodiscard]]
    static std::size_t ml_kem_ciphertext_size(const MlKemVariant v) noexcept {
        return ::ml_kem_ciphertext_size(v);
    }
    [[nodiscard]]
    static std::size_t ml_kem_shared_secret_size(const MlKemVariant v) noexcept {
        return ::ml_kem_shared_secret_size(v);
    }
    [[nodiscard]]
    static std::size_t ml_kem_private_key_export_size(const MlKemVariant v) noexcept {
        return ml_kem_private_key_size(v);
    }
    [[nodiscard]]
    static std::size_t ml_kem_public_key_export_size(const MlKemVariant v) noexcept {
        return ml_kem_public_key_size(v);
    }
    [[nodiscard]]
    static Status kem_encapsulate( // NOLINT(readability-function-size,readability-function-cognitive-complexity)
        const KeyId key, const Algorithm alg, // NOLINT(bugprone-easily-swappable-parameters)
        CryptoByte* const ciphertext,    std::size_t ciphertext_size,    std::size_t* const ciphertext_len,    // NOLINT(readability-non-const-parameter,bugprone-easily-swappable-parameters)
        CryptoByte* const shared_secret, std::size_t shared_secret_size, std::size_t* const shared_secret_len) noexcept { // NOLINT(readability-non-const-parameter,bugprone-easily-swappable-parameters)
#ifdef SAFE_CRYPTO_PQC_LIBOQS
        using psa_mbedtls::detail::PqcKeyType;
        if ((alg & kPqcAlgCategoryMask) != kAlgMlKemBase) { return PSA_ERROR_INVALID_ARGUMENT; }
        if (!psa_mbedtls::detail::pqc_key_id_is_pqc(static_cast<unsigned int>(key))) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        const auto kv_encaps = psa_mbedtls::detail::pqc_key_store_get_public(static_cast<unsigned int>(key));
        if (!kv_encaps || (kv_encaps->type != PqcKeyType::MlKemPublic && kv_encaps->type != PqcKeyType::MlKemPrivate)) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        const auto v = static_cast<MlKemVariant>(kv_encaps->variant);
        if (alg != alg_ml_kem(v)) { return PSA_ERROR_INVALID_ARGUMENT; }
        if (ciphertext_size    < ml_kem_ciphertext_size(v))    { return PSA_ERROR_BUFFER_TOO_SMALL; }
        if (shared_secret_size < ml_kem_shared_secret_size(v)) { return PSA_ERROR_BUFFER_TOO_SMALL; }
        if (!liboqs_pqc::ml_kem_encaps(v, kv_encaps->data.data(), kv_encaps->data.size(),
                                        ciphertext,    ciphertext_size,
                                        shared_secret, shared_secret_size)) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        *ciphertext_len    = ml_kem_ciphertext_size(v);
        *shared_secret_len = ml_kem_shared_secret_size(v);
        return PSA_SUCCESS;
#else
        (void)key; (void)alg;
        (void)ciphertext; (void)ciphertext_size; (void)ciphertext_len;
        (void)shared_secret; (void)shared_secret_size; (void)shared_secret_len;
        return err_invalid_arg;
#endif
    }
    [[nodiscard]]
    static Status kem_decapsulate( // NOLINT(readability-function-size,readability-function-cognitive-complexity)
        const KeyId key, const Algorithm alg, // NOLINT(bugprone-easily-swappable-parameters)
        const CryptoByte* const ciphertext, std::size_t ciphertext_len, // NOLINT(bugprone-easily-swappable-parameters)
        CryptoByte* const shared_secret, std::size_t shared_secret_size, std::size_t* const shared_secret_len) noexcept { // NOLINT(readability-non-const-parameter,bugprone-easily-swappable-parameters)
#ifdef SAFE_CRYPTO_PQC_LIBOQS
        using psa_mbedtls::detail::PqcKeyType;
        if ((alg & kPqcAlgCategoryMask) != kAlgMlKemBase) { return PSA_ERROR_INVALID_ARGUMENT; }
        if (!psa_mbedtls::detail::pqc_key_id_is_pqc(static_cast<unsigned int>(key))) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        const auto kv_decaps = psa_mbedtls::detail::pqc_key_store_get_private(static_cast<unsigned int>(key));
        if (!kv_decaps || kv_decaps->type != PqcKeyType::MlKemPrivate) { return PSA_ERROR_INVALID_ARGUMENT; }
        const auto v = static_cast<MlKemVariant>(kv_decaps->variant);
        if (alg != alg_ml_kem(v)) { return PSA_ERROR_INVALID_ARGUMENT; }
        if (shared_secret_size < ml_kem_shared_secret_size(v)) { return PSA_ERROR_BUFFER_TOO_SMALL; }
        if (!liboqs_pqc::ml_kem_decaps(v, kv_decaps->data.data(), kv_decaps->data.size(),
                                        ciphertext, ciphertext_len,
                                        shared_secret, shared_secret_size)) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        *shared_secret_len = ml_kem_shared_secret_size(v);
        return PSA_SUCCESS;
#else
        (void)key; (void)alg;
        (void)ciphertext; (void)ciphertext_len;
        (void)shared_secret; (void)shared_secret_size; (void)shared_secret_len;
        return err_invalid_arg;
#endif
    }
};
