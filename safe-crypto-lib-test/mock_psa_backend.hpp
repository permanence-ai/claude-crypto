// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <algorithm>
#include <cstddef>
#include <expected>

#include <gmock/gmock.h>
#include <psa/crypto.h>

#include "crypto_provider.hpp"
#include "defs.hpp"
#include "ml_dsa_variant.hpp"
#include "ml_kem_variant.hpp"
#include "psa_mbedtls_backend.hpp"
#include "sha_variant.hpp"
#include "slh_dsa_variant.hpp"


// GMock-based mock for all PSA operations.  Tests instantiate _impl<MockPsaBackend>
// directly and configure expectations via the global g_mock_psa pointer.
class MockPsaOps {
public:
    MOCK_METHOD(psa_status_t, crypto_init, (), ());
    MOCK_METHOD(psa_status_t, generate_random, (CryptoByte*, std::size_t), ());
    MOCK_METHOD(psa_status_t, hash_compute,
        (psa_algorithm_t, const CryptoByte*, std::size_t,
         CryptoByte*, std::size_t, std::size_t*), ());
    MOCK_METHOD(psa_status_t, import_key,
        (const psa_key_attributes_t*, const CryptoByte*, std::size_t,
         mbedtls_svc_key_id_t*), ());
    MOCK_METHOD(psa_status_t, generate_key,
        (const psa_key_attributes_t*, mbedtls_svc_key_id_t*), ());
    MOCK_METHOD(psa_status_t, destroy_key, (mbedtls_svc_key_id_t), ());
    MOCK_METHOD(psa_status_t, export_key,
        (mbedtls_svc_key_id_t, CryptoByte*, std::size_t, std::size_t*), ());
    MOCK_METHOD(psa_status_t, export_public_key,
        (mbedtls_svc_key_id_t, CryptoByte*, std::size_t, std::size_t*), ());
    MOCK_METHOD(psa_status_t, mac_compute,  // NOLINT(readability-function-size)
        (mbedtls_svc_key_id_t, psa_algorithm_t,
         const CryptoByte*, std::size_t,
         CryptoByte*, std::size_t, std::size_t*), ());
    MOCK_METHOD(psa_status_t, mac_verify,
        (mbedtls_svc_key_id_t, psa_algorithm_t,
         const CryptoByte*, std::size_t,
         const CryptoByte*, std::size_t), ());
    MOCK_METHOD(psa_status_t, aead_encrypt,  // NOLINT(readability-function-size)
        (mbedtls_svc_key_id_t, psa_algorithm_t,
         const CryptoByte*, std::size_t,
         const CryptoByte*, std::size_t,
         const CryptoByte*, std::size_t,
         CryptoByte*, std::size_t, std::size_t*), ());
    MOCK_METHOD(psa_status_t, aead_decrypt,  // NOLINT(readability-function-size)
        (mbedtls_svc_key_id_t, psa_algorithm_t,
         const CryptoByte*, std::size_t,
         const CryptoByte*, std::size_t,
         const CryptoByte*, std::size_t,
         CryptoByte*, std::size_t, std::size_t*), ());
    MOCK_METHOD(psa_status_t, sign_message,  // NOLINT(readability-function-size)
        (mbedtls_svc_key_id_t, psa_algorithm_t,
         const CryptoByte*, std::size_t,
         CryptoByte*, std::size_t, std::size_t*), ());
    MOCK_METHOD(psa_status_t, verify_message,
        (mbedtls_svc_key_id_t, psa_algorithm_t,
         const CryptoByte*, std::size_t,
         const CryptoByte*, std::size_t), ());
    MOCK_METHOD(psa_status_t, raw_key_agreement,  // NOLINT(readability-function-size)
        (psa_algorithm_t, mbedtls_svc_key_id_t,
         const CryptoByte*, std::size_t,
         CryptoByte*, std::size_t, std::size_t*), ());
    MOCK_METHOD(psa_status_t, asymmetric_encrypt,  // NOLINT(readability-function-size)
        (mbedtls_svc_key_id_t, psa_algorithm_t,
         const CryptoByte*, std::size_t,
         const CryptoByte*, std::size_t,
         CryptoByte*, std::size_t, std::size_t*), ());
    MOCK_METHOD(psa_status_t, asymmetric_decrypt,  // NOLINT(readability-function-size)
        (mbedtls_svc_key_id_t, psa_algorithm_t,
         const CryptoByte*, std::size_t,
         const CryptoByte*, std::size_t,
         CryptoByte*, std::size_t, std::size_t*), ());
    MOCK_METHOD(psa_status_t, hkdf_derive,
        (const CryptoByte*, std::size_t,
         const CryptoByte*, std::size_t,
         const CryptoByte*, std::size_t,
         std::size_t, bool), ());
};

inline MockPsaOps* g_mock_psa = nullptr;  // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

struct MockPsaBackend {
    using Status        = psa_status_t;
    using KeyId         = mbedtls_svc_key_id_t;
    using Algorithm     = psa_algorithm_t;
    using KeyAttributes = PsaKeyAttributes;

    static constexpr Status ok              = PSA_SUCCESS;
    static constexpr Status err_invalid_sig = PSA_ERROR_INVALID_SIGNATURE;
    static constexpr Status err_invalid_arg = PSA_ERROR_INVALID_ARGUMENT;

    static KeyId null_key_id() noexcept {
        const KeyId k = MBEDTLS_SVC_KEY_ID_INIT;
        return k;
    }
    static KeyAttributes make_key_attrs() noexcept {
        return {};
    }

    static psa_status_t crypto_init() {
        return g_mock_psa->crypto_init();
    }
    static auto generate_random(const std::size_t len)
        -> std::expected<SecureBuffer, Status>
    {
        SecureBuffer output(len);
        const auto s = g_mock_psa->generate_random(output.data(), len);
        if (s != PSA_SUCCESS) {
            return std::unexpected(s);
        }
        return output;
    }
    static auto hash_compute(
        const psa_algorithm_t alg,
        const CryptoByte* in, const std::size_t in_len)
        -> std::expected<SecureBuffer, Status>
    {
        SecureBuffer hash(PSA_HASH_MAX_SIZE);
        std::size_t hash_len = 0;
        const auto s = g_mock_psa->hash_compute(alg, in, in_len, hash.data(), PSA_HASH_MAX_SIZE, &hash_len);
        if (s != PSA_SUCCESS) {
            return std::unexpected(s);
        }
        hash.resize(hash_len);
        return hash;
    }
    static auto import_key(
        const PsaKeyAttributes* attrs,
        const CryptoByte* data, const std::size_t data_len)
        -> std::expected<KeyId, Status>
    {
        KeyId key = null_key_id();
        const auto s = g_mock_psa->import_key(attrs != nullptr ? &attrs->psa : nullptr, data, data_len, &key);
        if (s != PSA_SUCCESS) {
            return std::unexpected(s);
        }
        return key;
    }
    static auto generate_key(const PsaKeyAttributes* attrs)
        -> std::expected<KeyId, Status>
    {
        KeyId key = null_key_id();
        const auto s = g_mock_psa->generate_key(attrs != nullptr ? &attrs->psa : nullptr, &key);
        if (s != PSA_SUCCESS) {
            return std::unexpected(s);
        }
        return key;
    }
    static psa_status_t destroy_key(const mbedtls_svc_key_id_t key) {
        return g_mock_psa->destroy_key(key);
    }
    static auto export_key(const mbedtls_svc_key_id_t key)
        -> std::expected<SecureBuffer, Status>
    {
        SecureBuffer out(PSA_EXPORT_KEY_PAIR_MAX_SIZE);
        std::size_t out_len = 0;
        const auto s = g_mock_psa->export_key(key, out.data(), out.size(), &out_len);
        if (s != PSA_SUCCESS) { return std::unexpected(s); }
        out.resize(out_len);
        return out;
    }
    static auto export_public_key(const mbedtls_svc_key_id_t key)
        -> std::expected<SecureBuffer, Status>
    {
        SecureBuffer out(PSA_EXPORT_PUBLIC_KEY_MAX_SIZE);
        std::size_t out_len = 0;
        const auto s = g_mock_psa->export_public_key(key, out.data(), out.size(), &out_len);
        if (s != PSA_SUCCESS) { return std::unexpected(s); }
        out.resize(out_len);
        return out;
    }
    static auto mac_compute(  // NOLINT(readability-function-size)
        const mbedtls_svc_key_id_t key, const psa_algorithm_t alg,
        const CryptoByte* in, const std::size_t in_len)
        -> std::expected<SecureBuffer, Status>
    {
        SecureBuffer mac(PSA_MAC_MAX_SIZE);
        std::size_t mac_len = 0;
        const auto s = g_mock_psa->mac_compute(key, alg, in, in_len, mac.data(), PSA_MAC_MAX_SIZE, &mac_len);
        if (s != PSA_SUCCESS) {
            return std::unexpected(s);
        }
        mac.resize(mac_len);
        return mac;
    }
    static psa_status_t mac_verify(
        const mbedtls_svc_key_id_t key, const psa_algorithm_t alg,
        const CryptoByte* in, const std::size_t in_len,
        const CryptoByte* mac, const std::size_t mac_len)
    {
        return g_mock_psa->mac_verify(key, alg, in, in_len, mac, mac_len);
    }
    static auto aead_encrypt(  // NOLINT(readability-function-size)
        const mbedtls_svc_key_id_t key, const psa_algorithm_t alg,
        const CryptoByte* nonce, const std::size_t nonce_len,
        const CryptoByte* aad, const std::size_t aad_len,
        const CryptoByte* pt, const std::size_t pt_len)
        -> std::expected<SecureBuffer, Status>
    {
        const std::size_t ct_max = PSA_AEAD_ENCRYPT_OUTPUT_MAX_SIZE(pt_len);
        SecureBuffer ct(ct_max);
        std::size_t ct_len = 0;
        const auto s = g_mock_psa->aead_encrypt(
            key, alg, nonce, nonce_len, aad, aad_len, pt, pt_len, ct.data(), ct_max, &ct_len);
        if (s != PSA_SUCCESS) { return std::unexpected(s); }
        ct.resize(ct_len);
        return ct;
    }
    static auto aead_decrypt(  // NOLINT(readability-function-size)
        const mbedtls_svc_key_id_t key, const psa_algorithm_t alg,
        const CryptoByte* nonce, const std::size_t nonce_len,
        const CryptoByte* aad, const std::size_t aad_len,
        const CryptoByte* ct, const std::size_t ct_len)
        -> std::expected<SecureBuffer, Status>
    {
        SecureBuffer pt(ct_len);
        std::size_t pt_len = 0;
        const auto s = g_mock_psa->aead_decrypt(
            key, alg, nonce, nonce_len, aad, aad_len, ct, ct_len, pt.data(), pt.size(), &pt_len);
        if (s != PSA_SUCCESS) { return std::unexpected(s); }
        pt.resize(pt_len);
        return pt;
    }
    static auto sign_message(  // NOLINT(readability-function-size)
        const mbedtls_svc_key_id_t key, const psa_algorithm_t alg,
        const CryptoByte* in, const std::size_t in_len)
        -> std::expected<SecureBuffer, Status>
    {
        SecureBuffer sig(PSA_SIGNATURE_MAX_SIZE);
        std::size_t sig_len = 0;
        const auto s = g_mock_psa->sign_message(key, alg, in, in_len, sig.data(), PSA_SIGNATURE_MAX_SIZE, &sig_len);
        if (s != PSA_SUCCESS) {
            return std::unexpected(s);
        }
        sig.resize(sig_len);
        return sig;
    }
    static psa_status_t verify_message(
        const mbedtls_svc_key_id_t key, const psa_algorithm_t alg,
        const CryptoByte* in, const std::size_t in_len,
        const CryptoByte* sig, const std::size_t sig_len)
    {
        return g_mock_psa->verify_message(key, alg, in, in_len, sig, sig_len);
    }
    static auto raw_key_agreement(  // NOLINT(readability-function-size)
        const psa_algorithm_t alg, const mbedtls_svc_key_id_t priv_key,
        const CryptoByte* peer, const std::size_t peer_len)
        -> std::expected<SecureBuffer, Status>
    {
        const std::size_t max_size = PSA_RAW_KEY_AGREEMENT_OUTPUT_MAX_SIZE;
        SecureBuffer out(max_size);
        std::size_t out_len = 0;
        const auto s = g_mock_psa->raw_key_agreement(alg, priv_key, peer, peer_len, out.data(), max_size, &out_len);
        if (s != PSA_SUCCESS) { return std::unexpected(s); }
        out.resize(out_len);
        return out;
    }
    static auto asymmetric_encrypt(  // NOLINT(readability-function-size)
        const mbedtls_svc_key_id_t key, const psa_algorithm_t alg,
        const CryptoByte* in, const std::size_t in_len,
        const CryptoByte* salt, const std::size_t salt_len)
        -> std::expected<SecureBuffer, Status>
    {
        const std::size_t max_size = PSA_ASYMMETRIC_ENCRYPT_OUTPUT_MAX_SIZE;
        SecureBuffer out(max_size);
        std::size_t out_len = 0;
        const auto s = g_mock_psa->asymmetric_encrypt(
            key, alg, in, in_len, salt, salt_len, out.data(), max_size, &out_len);
        if (s != PSA_SUCCESS) { return std::unexpected(s); }
        out.resize(out_len);
        return out;
    }
    static auto asymmetric_decrypt(  // NOLINT(readability-function-size)
        const mbedtls_svc_key_id_t key, const psa_algorithm_t alg,
        const CryptoByte* in, const std::size_t in_len,
        const CryptoByte* salt, const std::size_t salt_len)
        -> std::expected<SecureBuffer, Status>
    {
        const std::size_t max_size = PSA_ASYMMETRIC_DECRYPT_OUTPUT_MAX_SIZE;
        SecureBuffer out(max_size);
        std::size_t out_len = 0;
        const auto s = g_mock_psa->asymmetric_decrypt(
            key, alg, in, in_len, salt, salt_len, out.data(), max_size, &out_len);
        if (s != PSA_SUCCESS) { return std::unexpected(s); }
        out.resize(out_len);
        return out;
    }
    static auto hkdf_derive(
        const CryptoByte* ikm,  const std::size_t ikm_len,
        const CryptoByte* salt, const std::size_t salt_len,
        const CryptoByte* info, const std::size_t info_len,
        const std::size_t out_len, const bool expand_only)
        -> std::expected<SecureBuffer, Status>
    {
        const auto s = g_mock_psa->hkdf_derive(
            ikm, ikm_len, salt, salt_len, info, info_len, out_len, expand_only);
        if (s != PSA_SUCCESS) { return std::unexpected(s); }
        return SecureBuffer(out_len);
    }

    // Algorithm constants, key attribute factories, and output size helpers are
    // pure functions with no mockable side effects — delegate to RealPsaBackend.
    static Algorithm alg_sha(const ShaVariant v) noexcept {
        return RealPsaBackend::alg_sha(v);
    }
    static Algorithm alg_hmac(const ShaVariant v) noexcept {
        return RealPsaBackend::alg_hmac(v);
    }
    static constexpr Algorithm alg_ecdsa()             noexcept { return RealPsaBackend::alg_ecdsa(); }
    static constexpr Algorithm alg_ecdh()              noexcept { return RealPsaBackend::alg_ecdh(); }
    static constexpr Algorithm alg_aes_gcm()           noexcept { return RealPsaBackend::alg_aes_gcm(); }
    static constexpr Algorithm alg_chacha20_poly1305() noexcept { return RealPsaBackend::alg_chacha20_poly1305(); }
    static constexpr Algorithm alg_rsa_oaep()          noexcept { return RealPsaBackend::alg_rsa_oaep(); }
    static constexpr Algorithm alg_rsa_pss()           noexcept { return RealPsaBackend::alg_rsa_pss(); }
    static Algorithm alg_slh_dsa(const SlhDsaVariant v) noexcept { return RealPsaBackend::alg_slh_dsa(v); }
    static Algorithm alg_ml_dsa(const MlDsaVariant v)   noexcept { return RealPsaBackend::alg_ml_dsa(v); }
    static Algorithm alg_ml_kem(const MlKemVariant v)   noexcept { return RealPsaBackend::alg_ml_kem(v); }

    static KeyAttributes make_hmac_generate_attrs(const ShaVariant v, const std::size_t key_size_bits) noexcept {
        return RealPsaBackend::make_hmac_generate_attrs(v, key_size_bits);
    }
    static KeyAttributes make_hmac_verify_attrs(const ShaVariant v, const std::size_t key_size_bits) noexcept {
        return RealPsaBackend::make_hmac_verify_attrs(v, key_size_bits);
    }
    static KeyAttributes make_ecdsa_generate_attrs(const std::size_t key_bits) noexcept {
        return RealPsaBackend::make_ecdsa_generate_attrs(key_bits);
    }
    static KeyAttributes make_ecdsa_sign_attrs(const std::size_t key_bits) noexcept {
        return RealPsaBackend::make_ecdsa_sign_attrs(key_bits);
    }
    static KeyAttributes make_ecdsa_verify_attrs(const std::size_t key_bits) noexcept {
        return RealPsaBackend::make_ecdsa_verify_attrs(key_bits);
    }
    static KeyAttributes make_ecdh_generate_attrs(const std::size_t key_bits) noexcept {
        return RealPsaBackend::make_ecdh_generate_attrs(key_bits);
    }
    static KeyAttributes make_ecdh_agree_attrs(const std::size_t key_bits) noexcept {
        return RealPsaBackend::make_ecdh_agree_attrs(key_bits);
    }
    static KeyAttributes make_aes256_gcm_encrypt_attrs() noexcept {
        return RealPsaBackend::make_aes256_gcm_encrypt_attrs();
    }
    static KeyAttributes make_aes256_gcm_decrypt_attrs() noexcept {
        return RealPsaBackend::make_aes256_gcm_decrypt_attrs();
    }
    static KeyAttributes make_chacha20_poly1305_encrypt_attrs() noexcept {
        return RealPsaBackend::make_chacha20_poly1305_encrypt_attrs();
    }
    static KeyAttributes make_chacha20_poly1305_decrypt_attrs() noexcept {
        return RealPsaBackend::make_chacha20_poly1305_decrypt_attrs();
    }
    static KeyAttributes make_rsa_oaep_encrypt_attrs(const std::size_t key_bits) noexcept {
        return RealPsaBackend::make_rsa_oaep_encrypt_attrs(key_bits);
    }
    static KeyAttributes make_rsa_oaep_decrypt_attrs(const std::size_t key_bits) noexcept {
        return RealPsaBackend::make_rsa_oaep_decrypt_attrs(key_bits);
    }
    static KeyAttributes make_rsa_pss_sign_attrs(const std::size_t key_bits) noexcept {
        return RealPsaBackend::make_rsa_pss_sign_attrs(key_bits);
    }
    static KeyAttributes make_rsa_pss_verify_attrs(const std::size_t key_bits) noexcept {
        return RealPsaBackend::make_rsa_pss_verify_attrs(key_bits);
    }
    static KeyAttributes make_rsa_key_pair_attrs(const std::size_t key_bits) noexcept {
        return RealPsaBackend::make_rsa_key_pair_attrs(key_bits);
    }
    static KeyAttributes make_slh_dsa_sign_attrs(const SlhDsaVariant v) noexcept {
        return RealPsaBackend::make_slh_dsa_sign_attrs(v);
    }
    static KeyAttributes make_slh_dsa_verify_attrs(const SlhDsaVariant v) noexcept {
        return RealPsaBackend::make_slh_dsa_verify_attrs(v);
    }
    static KeyAttributes make_slh_dsa_generate_attrs(const SlhDsaVariant v) noexcept {
        return RealPsaBackend::make_slh_dsa_generate_attrs(v);
    }
    static KeyAttributes make_ml_dsa_sign_attrs(const MlDsaVariant v) noexcept {
        return RealPsaBackend::make_ml_dsa_sign_attrs(v);
    }
    static KeyAttributes make_ml_dsa_verify_attrs(const MlDsaVariant v) noexcept {
        return RealPsaBackend::make_ml_dsa_verify_attrs(v);
    }
    static KeyAttributes make_ml_dsa_generate_attrs(const MlDsaVariant v) noexcept {
        return RealPsaBackend::make_ml_dsa_generate_attrs(v);
    }
    static KeyAttributes make_ml_kem_generate_attrs(const MlKemVariant v) noexcept {
        return RealPsaBackend::make_ml_kem_generate_attrs(v);
    }
    static KeyAttributes make_ml_kem_encap_attrs(const MlKemVariant v) noexcept {
        return RealPsaBackend::make_ml_kem_encap_attrs(v);
    }
    static KeyAttributes make_ml_kem_decap_attrs(const MlKemVariant v) noexcept {
        return RealPsaBackend::make_ml_kem_decap_attrs(v);
    }

    static std::size_t ecdsa_sign_output_size(const std::size_t key_bits) noexcept {
        return RealPsaBackend::ecdsa_sign_output_size(key_bits);
    }
    static std::size_t ecdh_shared_secret_size(const std::size_t key_bits) noexcept {
        return RealPsaBackend::ecdh_shared_secret_size(key_bits);
    }
    static std::size_t ec_private_key_export_size(const std::size_t key_bits) noexcept {
        return RealPsaBackend::ec_private_key_export_size(key_bits);
    }
    static std::size_t ec_public_key_export_size(const std::size_t key_bits) noexcept {
        return RealPsaBackend::ec_public_key_export_size(key_bits);
    }
    static std::size_t aes_gcm_encrypt_output_size(const std::size_t plaintext_size) noexcept {
        return RealPsaBackend::aes_gcm_encrypt_output_size(plaintext_size);
    }
    static std::size_t aes_gcm_decrypt_output_size(const std::size_t ciphertext_size) noexcept {
        return RealPsaBackend::aes_gcm_decrypt_output_size(ciphertext_size);
    }
    static std::size_t chacha20_encrypt_output_size(const std::size_t plaintext_size) noexcept {
        return RealPsaBackend::chacha20_encrypt_output_size(plaintext_size);
    }
    static std::size_t chacha20_decrypt_output_size(const std::size_t ciphertext_size) noexcept {
        return RealPsaBackend::chacha20_decrypt_output_size(ciphertext_size);
    }
    static std::size_t rsa_oaep_encrypt_output_size(const std::size_t key_bits) noexcept {
        return RealPsaBackend::rsa_oaep_encrypt_output_size(key_bits);
    }
    static std::size_t rsa_oaep_decrypt_output_size(const std::size_t key_bits) noexcept {
        return RealPsaBackend::rsa_oaep_decrypt_output_size(key_bits);
    }
    static std::size_t rsa_pss_sign_output_size(const std::size_t key_bits) noexcept {
        return RealPsaBackend::rsa_pss_sign_output_size(key_bits);
    }
    static std::size_t rsa_private_key_export_size(const std::size_t key_bits) noexcept {
        return RealPsaBackend::rsa_private_key_export_size(key_bits);
    }
    static std::size_t rsa_public_key_export_size(const std::size_t key_bits) noexcept {
        return RealPsaBackend::rsa_public_key_export_size(key_bits);
    }
    static std::size_t slh_dsa_sign_output_size(const SlhDsaVariant v) noexcept {
        return RealPsaBackend::slh_dsa_sign_output_size(v);
    }
    static std::size_t slh_dsa_private_key_export_size(const SlhDsaVariant v) noexcept {
        return RealPsaBackend::slh_dsa_private_key_export_size(v);
    }
    static std::size_t slh_dsa_public_key_export_size(const SlhDsaVariant v) noexcept {
        return RealPsaBackend::slh_dsa_public_key_export_size(v);
    }
    static std::size_t ml_dsa_sign_output_size(const MlDsaVariant v) noexcept {
        return RealPsaBackend::ml_dsa_sign_output_size(v);
    }
    static std::size_t ml_dsa_private_key_export_size(const MlDsaVariant v) noexcept {
        return RealPsaBackend::ml_dsa_private_key_export_size(v);
    }
    static std::size_t ml_dsa_public_key_export_size(const MlDsaVariant v) noexcept {
        return RealPsaBackend::ml_dsa_public_key_export_size(v);
    }
    static std::size_t ml_kem_ciphertext_size(const MlKemVariant v) noexcept {
        return RealPsaBackend::ml_kem_ciphertext_size(v);
    }
    static std::size_t ml_kem_shared_secret_size(const MlKemVariant v) noexcept {
        return RealPsaBackend::ml_kem_shared_secret_size(v);
    }
    static std::size_t ml_kem_private_key_export_size(const MlKemVariant v) noexcept {
        return RealPsaBackend::ml_kem_private_key_export_size(v);
    }
    static std::size_t ml_kem_public_key_export_size(const MlKemVariant v) noexcept {
        return RealPsaBackend::ml_kem_public_key_export_size(v);
    }
    static auto kem_encapsulate( // NOLINT(readability-function-size,readability-function-cognitive-complexity)
        const KeyId k, const Algorithm a) noexcept
        -> std::expected<KemEncapsulateResult, Status>
    {
        return RealPsaBackend::kem_encapsulate(k, a);
    }
    static auto kem_decapsulate( // NOLINT(readability-function-size,readability-function-cognitive-complexity)
        const KeyId k, const Algorithm a,
        const CryptoByte* ct, const std::size_t ct_len) noexcept
        -> std::expected<SecureBuffer, Status>
    {
        return RealPsaBackend::kem_decapsulate(k, a, ct, ct_len);
    }
};
