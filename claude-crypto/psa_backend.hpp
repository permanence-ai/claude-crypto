/*
Copyright Permanence AI, 2026. All rights reserved.

*/

#pragma once

#include <concepts>
#include <cstddef>

#include <psa/crypto.h>

#include "defs.hpp"


// Production PSA backend — every method is a direct forwarding call to the
// corresponding PSA C function.  Tests substitute MockPsaBackend to exercise
// error branches without needing to induce real PSA failures.
struct RealPsaBackend {
    static psa_status_t crypto_init() {
        return psa_crypto_init();
    }

    static psa_status_t generate_random(CryptoByte* output, const std::size_t output_size) {
        return psa_generate_random(output, output_size);
    }

    static psa_status_t hash_compute(
        const psa_algorithm_t alg,
        const CryptoByte* input, const std::size_t input_length,
        CryptoByte* hash, const std::size_t hash_size, std::size_t* hash_length)
    {
        return psa_hash_compute(alg, input, input_length, hash, hash_size, hash_length);
    }

    static psa_status_t import_key(
        const psa_key_attributes_t* attributes,
        const CryptoByte* data, const std::size_t data_length,
        mbedtls_svc_key_id_t* key)
    {
        return psa_import_key(attributes, data, data_length, key);
    }

    static psa_status_t generate_key(
        const psa_key_attributes_t* attributes,
        mbedtls_svc_key_id_t* key)
    {
        return psa_generate_key(attributes, key);
    }

    static psa_status_t destroy_key(const mbedtls_svc_key_id_t key) {
        return psa_destroy_key(key);
    }

    static psa_status_t export_key(
        const mbedtls_svc_key_id_t key,
        CryptoByte* data, const std::size_t data_size, std::size_t* data_length)
    {
        return psa_export_key(key, data, data_size, data_length);
    }

    static psa_status_t export_public_key(
        const mbedtls_svc_key_id_t key,
        CryptoByte* data, const std::size_t data_size, std::size_t* data_length)
    {
        return psa_export_public_key(key, data, data_size, data_length);
    }

    static psa_status_t mac_compute(  // NOLINT(readability-function-size)
        const mbedtls_svc_key_id_t key, const psa_algorithm_t alg,
        const CryptoByte* input, const std::size_t input_length,
        CryptoByte* mac, const std::size_t mac_size, std::size_t* mac_length)
    {
        return psa_mac_compute(key, alg, input, input_length, mac, mac_size, mac_length);
    }

    static psa_status_t mac_verify(
        const mbedtls_svc_key_id_t key, const psa_algorithm_t alg,
        const CryptoByte* input, const std::size_t input_length,
        const CryptoByte* mac, const std::size_t mac_length)
    {
        return psa_mac_verify(key, alg, input, input_length, mac, mac_length);
    }

    static psa_status_t aead_encrypt(  // NOLINT(readability-function-size)
        const mbedtls_svc_key_id_t key, const psa_algorithm_t alg,
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

    static psa_status_t aead_decrypt(  // NOLINT(readability-function-size)
        const mbedtls_svc_key_id_t key, const psa_algorithm_t alg,
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

    static psa_status_t sign_message(  // NOLINT(readability-function-size)
        const mbedtls_svc_key_id_t key, const psa_algorithm_t alg,
        const CryptoByte* input, const std::size_t input_length,
        CryptoByte* signature, const std::size_t signature_size,
        std::size_t* signature_length)
    {
        return psa_sign_message(
            key, alg, input, input_length,
            signature, signature_size, signature_length);
    }

    static psa_status_t verify_message(
        const mbedtls_svc_key_id_t key, const psa_algorithm_t alg,
        const CryptoByte* input, const std::size_t input_length,
        const CryptoByte* signature, const std::size_t signature_length)
    {
        return psa_verify_message(
            key, alg, input, input_length, signature, signature_length);
    }

    static psa_status_t raw_key_agreement(  // NOLINT(readability-function-size)
        const psa_algorithm_t alg,
        const mbedtls_svc_key_id_t private_key,
        const CryptoByte* peer_key, const std::size_t peer_key_length,
        CryptoByte* output, const std::size_t output_size,
        std::size_t* output_length)
    {
        return psa_raw_key_agreement(
            alg, private_key, peer_key, peer_key_length,
            output, output_size, output_length);
    }

    static psa_status_t asymmetric_encrypt(  // NOLINT(readability-function-size)
        const mbedtls_svc_key_id_t key, const psa_algorithm_t alg,
        const CryptoByte* input, const std::size_t input_length,
        const CryptoByte* salt, const std::size_t salt_length,
        CryptoByte* output, const std::size_t output_size,
        std::size_t* output_length)
    {
        return psa_asymmetric_encrypt(
            key, alg, input, input_length, salt, salt_length,
            output, output_size, output_length);
    }

    static psa_status_t asymmetric_decrypt(  // NOLINT(readability-function-size)
        const mbedtls_svc_key_id_t key, const psa_algorithm_t alg,
        const CryptoByte* input, const std::size_t input_length,
        const CryptoByte* salt, const std::size_t salt_length,
        CryptoByte* output, const std::size_t output_size,
        std::size_t* output_length)
    {
        return psa_asymmetric_decrypt(
            key, alg, input, input_length, salt, salt_length,
            output, output_size, output_length);
    }

    static psa_status_t key_derivation_setup(
        psa_key_derivation_operation_t* operation, const psa_algorithm_t alg)
    {
        return psa_key_derivation_setup(operation, alg);
    }

    static psa_status_t key_derivation_input_key(
        psa_key_derivation_operation_t* operation,
        const psa_key_derivation_step_t step,
        const mbedtls_svc_key_id_t key)
    {
        return psa_key_derivation_input_key(operation, step, key);
    }

    static psa_status_t key_derivation_input_bytes(
        psa_key_derivation_operation_t* operation,
        const psa_key_derivation_step_t step,
        const CryptoByte* data, const std::size_t data_length)
    {
        return psa_key_derivation_input_bytes(operation, step, data, data_length);
    }

    static psa_status_t key_derivation_output_bytes(
        psa_key_derivation_operation_t* operation,
        CryptoByte* output, const std::size_t output_length)
    {
        return psa_key_derivation_output_bytes(operation, output, output_length);
    }

    static psa_status_t key_derivation_abort(psa_key_derivation_operation_t* operation) {
        return psa_key_derivation_abort(operation);
    }
};


// Concept satisfied by any type that provides the full PSA Crypto C API surface
// used by this library.  The current wire type is the PSA Crypto API from
// MbedTLS, so all key handles are mbedtls_svc_key_id_t and algorithm selectors
// are psa_algorithm_t.  A future provider (OpenSSL, hardware) would either
// implement a PSA-compatible shim or this concept would need to grow associated
// types to abstract over the handle and algorithm representations.
template<typename T>
concept CryptoProvider = requires(
    T,
    psa_key_attributes_t*      attrs,
    mbedtls_svc_key_id_t       key,
    mbedtls_svc_key_id_t*      key_out,
    psa_algorithm_t            alg,
    psa_key_derivation_step_t  step,
    psa_key_derivation_operation_t* op,
    CryptoByte*                buf,
    const CryptoByte*          cbuf,
    std::size_t                len,
    std::size_t*               len_out)
{
    { T::crypto_init() }                                        -> std::same_as<psa_status_t>;
    { T::generate_random(buf, len) }                            -> std::same_as<psa_status_t>;
    { T::import_key(attrs, cbuf, len, key_out) }                -> std::same_as<psa_status_t>;
    { T::generate_key(attrs, key_out) }                         -> std::same_as<psa_status_t>;
    { T::destroy_key(key) }                                     -> std::same_as<psa_status_t>;
    { T::export_key(key, buf, len, len_out) }                   -> std::same_as<psa_status_t>;
    { T::export_public_key(key, buf, len, len_out) }            -> std::same_as<psa_status_t>;
    { T::sign_message(key, alg, cbuf, len, buf, len, len_out) } -> std::same_as<psa_status_t>;
    { T::verify_message(key, alg, cbuf, len, cbuf, len) }       -> std::same_as<psa_status_t>;
    { T::mac_compute(key, alg, cbuf, len, buf, len, len_out) }  -> std::same_as<psa_status_t>;
    { T::mac_verify(key, alg, cbuf, len, cbuf, len) }           -> std::same_as<psa_status_t>;
    { T::aead_encrypt(key, alg, cbuf, len, cbuf, len, cbuf, len, buf, len, len_out) } -> std::same_as<psa_status_t>;
    { T::aead_decrypt(key, alg, cbuf, len, cbuf, len, cbuf, len, buf, len, len_out) } -> std::same_as<psa_status_t>;
    { T::asymmetric_encrypt(key, alg, cbuf, len, cbuf, len, buf, len, len_out) }      -> std::same_as<psa_status_t>;
    { T::asymmetric_decrypt(key, alg, cbuf, len, cbuf, len, buf, len, len_out) }      -> std::same_as<psa_status_t>;
    { T::raw_key_agreement(alg, key, cbuf, len, buf, len, len_out) }                  -> std::same_as<psa_status_t>;
    { T::hash_compute(alg, cbuf, len, buf, len, len_out) }                            -> std::same_as<psa_status_t>;
    { T::key_derivation_setup(op, alg) }                        -> std::same_as<psa_status_t>;
    { T::key_derivation_input_key(op, step, key) }              -> std::same_as<psa_status_t>;
    { T::key_derivation_input_bytes(op, step, cbuf, len) }      -> std::same_as<psa_status_t>;
    { T::key_derivation_output_bytes(op, buf, len) }            -> std::same_as<psa_status_t>;
    { T::key_derivation_abort(op) }                             -> std::same_as<psa_status_t>;
};


template<CryptoProvider Provider>
class PsaKeyHandle {
public:
    PsaKeyHandle() = default;

    explicit PsaKeyHandle(const mbedtls_svc_key_id_t id) noexcept
        : id_(id), valid_(true) {}

    ~PsaKeyHandle() noexcept {  // NOLINT(bugprone-exception-escape)
        if (valid_) {
            Provider::destroy_key(id_);
        }
    }

    PsaKeyHandle(const PsaKeyHandle&)            = delete;
    PsaKeyHandle& operator=(const PsaKeyHandle&) = delete;

    PsaKeyHandle(PsaKeyHandle&& other) noexcept
        : id_(other.id_), valid_(other.valid_)
    {
        other.valid_ = false;
    }

    PsaKeyHandle& operator=(PsaKeyHandle&& other) noexcept {
        if (this != &other) {
            reset();
            id_          = other.id_;
            valid_       = other.valid_;
            other.valid_ = false;
        }
        return *this;
    }

    [[nodiscard]] auto get() const noexcept -> mbedtls_svc_key_id_t { return id_; }

    void reset() noexcept {
        if (valid_) {
            Provider::destroy_key(id_);
            valid_ = false;
        }
    }

private:
    mbedtls_svc_key_id_t id_    = MBEDTLS_SVC_KEY_ID_INIT;
    bool                 valid_ = false;
};
