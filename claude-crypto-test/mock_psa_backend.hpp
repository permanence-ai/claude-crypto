/*
Copyright Permanence AI, 2026. All rights reserved.

*/

#pragma once

#include <algorithm>
#include <cstddef>

#include <gmock/gmock.h>
#include <psa/crypto.h>

#include "defs.hpp"
#include "psa_backend.hpp"


// GMock-based mock for all PSA operations.  Tests instantiate _impl<MockPsaBackend>
// directly and configure expectations via the global g_mock_psa pointer.
class MockPsaOps {
public:
    MOCK_METHOD(psa_status_t, crypto_init, (), ());
    MOCK_METHOD(psa_status_t, generate_random, (CRYPTO_BYTE*, std::size_t), ());
    MOCK_METHOD(psa_status_t, hash_compute,
        (psa_algorithm_t, const CRYPTO_BYTE*, std::size_t,
         CRYPTO_BYTE*, std::size_t, std::size_t*), ());
    MOCK_METHOD(psa_status_t, import_key,
        (const psa_key_attributes_t*, const CRYPTO_BYTE*, std::size_t,
         mbedtls_svc_key_id_t*), ());
    MOCK_METHOD(psa_status_t, generate_key,
        (const psa_key_attributes_t*, mbedtls_svc_key_id_t*), ());
    MOCK_METHOD(psa_status_t, destroy_key, (mbedtls_svc_key_id_t), ());
    MOCK_METHOD(psa_status_t, export_key,
        (mbedtls_svc_key_id_t, CRYPTO_BYTE*, std::size_t, std::size_t*), ());
    MOCK_METHOD(psa_status_t, export_public_key,
        (mbedtls_svc_key_id_t, CRYPTO_BYTE*, std::size_t, std::size_t*), ());
    MOCK_METHOD(psa_status_t, mac_compute,
        (mbedtls_svc_key_id_t, psa_algorithm_t,
         const CRYPTO_BYTE*, std::size_t,
         CRYPTO_BYTE*, std::size_t, std::size_t*), ());
    MOCK_METHOD(psa_status_t, mac_verify,
        (mbedtls_svc_key_id_t, psa_algorithm_t,
         const CRYPTO_BYTE*, std::size_t,
         const CRYPTO_BYTE*, std::size_t), ());
    MOCK_METHOD(psa_status_t, aead_encrypt,
        (mbedtls_svc_key_id_t, psa_algorithm_t,
         const CRYPTO_BYTE*, std::size_t,
         const CRYPTO_BYTE*, std::size_t,
         const CRYPTO_BYTE*, std::size_t,
         CRYPTO_BYTE*, std::size_t, std::size_t*), ());
    MOCK_METHOD(psa_status_t, aead_decrypt,
        (mbedtls_svc_key_id_t, psa_algorithm_t,
         const CRYPTO_BYTE*, std::size_t,
         const CRYPTO_BYTE*, std::size_t,
         const CRYPTO_BYTE*, std::size_t,
         CRYPTO_BYTE*, std::size_t, std::size_t*), ());
    MOCK_METHOD(psa_status_t, sign_message,
        (mbedtls_svc_key_id_t, psa_algorithm_t,
         const CRYPTO_BYTE*, std::size_t,
         CRYPTO_BYTE*, std::size_t, std::size_t*), ());
    MOCK_METHOD(psa_status_t, verify_message,
        (mbedtls_svc_key_id_t, psa_algorithm_t,
         const CRYPTO_BYTE*, std::size_t,
         const CRYPTO_BYTE*, std::size_t), ());
    MOCK_METHOD(psa_status_t, raw_key_agreement,
        (psa_algorithm_t, mbedtls_svc_key_id_t,
         const CRYPTO_BYTE*, std::size_t,
         CRYPTO_BYTE*, std::size_t, std::size_t*), ());
    MOCK_METHOD(psa_status_t, asymmetric_encrypt,
        (mbedtls_svc_key_id_t, psa_algorithm_t,
         const CRYPTO_BYTE*, std::size_t,
         const CRYPTO_BYTE*, std::size_t,
         CRYPTO_BYTE*, std::size_t, std::size_t*), ());
    MOCK_METHOD(psa_status_t, asymmetric_decrypt,
        (mbedtls_svc_key_id_t, psa_algorithm_t,
         const CRYPTO_BYTE*, std::size_t,
         const CRYPTO_BYTE*, std::size_t,
         CRYPTO_BYTE*, std::size_t, std::size_t*), ());
    MOCK_METHOD(psa_status_t, key_derivation_setup,
        (psa_key_derivation_operation_t*, psa_algorithm_t), ());
    MOCK_METHOD(psa_status_t, key_derivation_input_key,
        (psa_key_derivation_operation_t*, psa_key_derivation_step_t,
         mbedtls_svc_key_id_t), ());
    MOCK_METHOD(psa_status_t, key_derivation_input_bytes,
        (psa_key_derivation_operation_t*, psa_key_derivation_step_t,
         const CRYPTO_BYTE*, std::size_t), ());
    MOCK_METHOD(psa_status_t, key_derivation_output_bytes,
        (psa_key_derivation_operation_t*, CRYPTO_BYTE*, std::size_t), ());
    MOCK_METHOD(psa_status_t, key_derivation_abort,
        (psa_key_derivation_operation_t*), ());
};

inline MockPsaOps* g_mock_psa = nullptr;  // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

struct MockPsaBackend {
    static psa_status_t crypto_init() {
        return g_mock_psa->crypto_init();
    }
    static psa_status_t generate_random(CRYPTO_BYTE* out, const std::size_t len) {
        return g_mock_psa->generate_random(out, len);
    }
    static psa_status_t hash_compute(
        const psa_algorithm_t alg,
        const CRYPTO_BYTE* in, const std::size_t in_len,
        CRYPTO_BYTE* hash, const std::size_t hash_size, std::size_t* hash_len)
    {
        return g_mock_psa->hash_compute(alg, in, in_len, hash, hash_size, hash_len);
    }
    static psa_status_t import_key(
        const psa_key_attributes_t* attrs,
        const CRYPTO_BYTE* data, const std::size_t data_len,
        mbedtls_svc_key_id_t* key)
    {
        return g_mock_psa->import_key(attrs, data, data_len, key);
    }
    static psa_status_t generate_key(
        const psa_key_attributes_t* attrs, mbedtls_svc_key_id_t* key)
    {
        return g_mock_psa->generate_key(attrs, key);
    }
    static psa_status_t destroy_key(const mbedtls_svc_key_id_t key) {
        return g_mock_psa->destroy_key(key);
    }
    static psa_status_t export_key(
        const mbedtls_svc_key_id_t key,
        CRYPTO_BYTE* data, const std::size_t size, std::size_t* len)
    {
        return g_mock_psa->export_key(key, data, size, len);
    }
    static psa_status_t export_public_key(
        const mbedtls_svc_key_id_t key,
        CRYPTO_BYTE* data, const std::size_t size, std::size_t* len)
    {
        return g_mock_psa->export_public_key(key, data, size, len);
    }
    static psa_status_t mac_compute(
        const mbedtls_svc_key_id_t key, const psa_algorithm_t alg,
        const CRYPTO_BYTE* in, const std::size_t in_len,
        CRYPTO_BYTE* mac, const std::size_t mac_size, std::size_t* mac_len)
    {
        return g_mock_psa->mac_compute(key, alg, in, in_len, mac, mac_size, mac_len);
    }
    static psa_status_t mac_verify(
        const mbedtls_svc_key_id_t key, const psa_algorithm_t alg,
        const CRYPTO_BYTE* in, const std::size_t in_len,
        const CRYPTO_BYTE* mac, const std::size_t mac_len)
    {
        return g_mock_psa->mac_verify(key, alg, in, in_len, mac, mac_len);
    }
    static psa_status_t aead_encrypt(
        const mbedtls_svc_key_id_t key, const psa_algorithm_t alg,
        const CRYPTO_BYTE* nonce, const std::size_t nonce_len,
        const CRYPTO_BYTE* aad, const std::size_t aad_len,
        const CRYPTO_BYTE* pt, const std::size_t pt_len,
        CRYPTO_BYTE* ct, const std::size_t ct_size, std::size_t* ct_len)
    {
        return g_mock_psa->aead_encrypt(
            key, alg, nonce, nonce_len, aad, aad_len, pt, pt_len, ct, ct_size, ct_len);
    }
    static psa_status_t aead_decrypt(
        const mbedtls_svc_key_id_t key, const psa_algorithm_t alg,
        const CRYPTO_BYTE* nonce, const std::size_t nonce_len,
        const CRYPTO_BYTE* aad, const std::size_t aad_len,
        const CRYPTO_BYTE* ct, const std::size_t ct_len,
        CRYPTO_BYTE* pt, const std::size_t pt_size, std::size_t* pt_len)
    {
        return g_mock_psa->aead_decrypt(
            key, alg, nonce, nonce_len, aad, aad_len, ct, ct_len, pt, pt_size, pt_len);
    }
    static psa_status_t sign_message(
        const mbedtls_svc_key_id_t key, const psa_algorithm_t alg,
        const CRYPTO_BYTE* in, const std::size_t in_len,
        CRYPTO_BYTE* sig, const std::size_t sig_size, std::size_t* sig_len)
    {
        return g_mock_psa->sign_message(key, alg, in, in_len, sig, sig_size, sig_len);
    }
    static psa_status_t verify_message(
        const mbedtls_svc_key_id_t key, const psa_algorithm_t alg,
        const CRYPTO_BYTE* in, const std::size_t in_len,
        const CRYPTO_BYTE* sig, const std::size_t sig_len)
    {
        return g_mock_psa->verify_message(key, alg, in, in_len, sig, sig_len);
    }
    static psa_status_t raw_key_agreement(
        const psa_algorithm_t alg, const mbedtls_svc_key_id_t priv_key,
        const CRYPTO_BYTE* peer, const std::size_t peer_len,
        CRYPTO_BYTE* out, const std::size_t out_size, std::size_t* out_len)
    {
        return g_mock_psa->raw_key_agreement(alg, priv_key, peer, peer_len, out, out_size, out_len);
    }
    static psa_status_t asymmetric_encrypt(
        const mbedtls_svc_key_id_t key, const psa_algorithm_t alg,
        const CRYPTO_BYTE* in, const std::size_t in_len,
        const CRYPTO_BYTE* salt, const std::size_t salt_len,
        CRYPTO_BYTE* out, const std::size_t out_size, std::size_t* out_len)
    {
        return g_mock_psa->asymmetric_encrypt(
            key, alg, in, in_len, salt, salt_len, out, out_size, out_len);
    }
    static psa_status_t asymmetric_decrypt(
        const mbedtls_svc_key_id_t key, const psa_algorithm_t alg,
        const CRYPTO_BYTE* in, const std::size_t in_len,
        const CRYPTO_BYTE* salt, const std::size_t salt_len,
        CRYPTO_BYTE* out, const std::size_t out_size, std::size_t* out_len)
    {
        return g_mock_psa->asymmetric_decrypt(
            key, alg, in, in_len, salt, salt_len, out, out_size, out_len);
    }
    static psa_status_t key_derivation_setup(
        psa_key_derivation_operation_t* op, const psa_algorithm_t alg)
    {
        return g_mock_psa->key_derivation_setup(op, alg);
    }
    static psa_status_t key_derivation_input_key(
        psa_key_derivation_operation_t* op, const psa_key_derivation_step_t step,
        const mbedtls_svc_key_id_t key)
    {
        return g_mock_psa->key_derivation_input_key(op, step, key);
    }
    static psa_status_t key_derivation_input_bytes(
        psa_key_derivation_operation_t* op, const psa_key_derivation_step_t step,
        const CRYPTO_BYTE* data, const std::size_t data_len)
    {
        return g_mock_psa->key_derivation_input_bytes(op, step, data, data_len);
    }
    static psa_status_t key_derivation_output_bytes(
        psa_key_derivation_operation_t* op, CRYPTO_BYTE* out, const std::size_t out_len)
    {
        return g_mock_psa->key_derivation_output_bytes(op, out, out_len);
    }
    static psa_status_t key_derivation_abort(psa_key_derivation_operation_t* op) {
        return g_mock_psa->key_derivation_abort(op);
    }
};
