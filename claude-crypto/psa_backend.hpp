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
    // Associated types — insulate callers from PSA/MbedTLS concrete type names.
    using Status        = psa_status_t;
    using KeyId         = mbedtls_svc_key_id_t;
    using Algorithm     = psa_algorithm_t;
    using KeyAttributes = psa_key_attributes_t;
    using KdfOperation  = psa_key_derivation_operation_t;
    using KdfStep       = psa_key_derivation_step_t;

    // Status sentinels — avoids PSA_SUCCESS / PSA_ERROR_* leaking into generic code.
    static constexpr Status ok              = PSA_SUCCESS;
    static constexpr Status err_invalid_sig = PSA_ERROR_INVALID_SIGNATURE;
    static constexpr Status err_invalid_arg = PSA_ERROR_INVALID_ARGUMENT;

    // Object factories for provider-specific init macros.
    static KeyId null_key_id() noexcept {
        const KeyId k = MBEDTLS_SVC_KEY_ID_INIT;
        return k;
    }
    static KeyAttributes make_key_attrs() noexcept {
        KeyAttributes a = PSA_KEY_ATTRIBUTES_INIT;
        return a;
    }
    static KdfOperation make_kdf_op() noexcept {
        KdfOperation o = PSA_KEY_DERIVATION_OPERATION_INIT;
        return o;
    }

    static Status crypto_init() {
        return psa_crypto_init();
    }

    static Status generate_random(CryptoByte* output, const std::size_t output_size) {
        return psa_generate_random(output, output_size);
    }

    static Status hash_compute(
        const Algorithm alg,
        const CryptoByte* input, const std::size_t input_length,
        CryptoByte* hash, const std::size_t hash_size, std::size_t* hash_length)
    {
        return psa_hash_compute(alg, input, input_length, hash, hash_size, hash_length);
    }

    static Status import_key(
        const KeyAttributes* attributes,
        const CryptoByte* data, const std::size_t data_length,
        KeyId* key)
    {
        return psa_import_key(attributes, data, data_length, key);
    }

    static Status generate_key(
        const KeyAttributes* attributes,
        KeyId* key)
    {
        return psa_generate_key(attributes, key);
    }

    static Status destroy_key(const KeyId key) {
        return psa_destroy_key(key);
    }

    static Status export_key(
        const KeyId key,
        CryptoByte* data, const std::size_t data_size, std::size_t* data_length)
    {
        return psa_export_key(key, data, data_size, data_length);
    }

    static Status export_public_key(
        const KeyId key,
        CryptoByte* data, const std::size_t data_size, std::size_t* data_length)
    {
        return psa_export_public_key(key, data, data_size, data_length);
    }

    static Status mac_compute(  // NOLINT(readability-function-size)
        const KeyId key, const Algorithm alg,
        const CryptoByte* input, const std::size_t input_length,
        CryptoByte* mac, const std::size_t mac_size, std::size_t* mac_length)
    {
        return psa_mac_compute(key, alg, input, input_length, mac, mac_size, mac_length);
    }

    static Status mac_verify(
        const KeyId key, const Algorithm alg,
        const CryptoByte* input, const std::size_t input_length,
        const CryptoByte* mac, const std::size_t mac_length)
    {
        return psa_mac_verify(key, alg, input, input_length, mac, mac_length);
    }

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

    static Status sign_message(  // NOLINT(readability-function-size)
        const KeyId key, const Algorithm alg,
        const CryptoByte* input, const std::size_t input_length,
        CryptoByte* signature, const std::size_t signature_size,
        std::size_t* signature_length)
    {
        return psa_sign_message(
            key, alg, input, input_length,
            signature, signature_size, signature_length);
    }

    static Status verify_message(
        const KeyId key, const Algorithm alg,
        const CryptoByte* input, const std::size_t input_length,
        const CryptoByte* signature, const std::size_t signature_length)
    {
        return psa_verify_message(
            key, alg, input, input_length, signature, signature_length);
    }

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

    static Status key_derivation_setup(
        KdfOperation* operation, const Algorithm alg)
    {
        return psa_key_derivation_setup(operation, alg);
    }

    static Status key_derivation_input_key(
        KdfOperation* operation,
        const KdfStep step,
        const KeyId key)
    {
        return psa_key_derivation_input_key(operation, step, key);
    }

    static Status key_derivation_input_bytes(
        KdfOperation* operation,
        const KdfStep step,
        const CryptoByte* data, const std::size_t data_length)
    {
        return psa_key_derivation_input_bytes(operation, step, data, data_length);
    }

    static Status key_derivation_output_bytes(
        KdfOperation* operation,
        CryptoByte* output, const std::size_t output_length)
    {
        return psa_key_derivation_output_bytes(operation, output, output_length);
    }

    static Status key_derivation_abort(KdfOperation* operation) {
        return psa_key_derivation_abort(operation);
    }
};


// Concept satisfied by any CryptoProvider implementation.  Providers expose
// associated types (Status, KeyId, Algorithm, KeyAttributes, KdfOperation,
// KdfStep) and factory functions (null_key_id, make_key_attrs, make_kdf_op)
// so that _impl bodies never reference PSA/MbedTLS concrete type names directly.
// A future OpenSSL or hardware-ASM provider supplies its own type aliases and
// wraps its native API surface behind this same interface.
template<typename T>
concept CryptoProvider = requires(
    T,
    T::KeyAttributes*  attrs,
    T::KeyId           key,
    T::KeyId*          key_out,
    T::Algorithm       alg,
    T::KdfStep         step,
    T::KdfOperation*   op,
    CryptoByte*        buf,
    const CryptoByte*  cbuf,
    std::size_t        len,
    std::size_t*       len_out)
{
    typename T::Status;
    typename T::KeyId;
    typename T::Algorithm;
    typename T::KeyAttributes;
    typename T::KdfOperation;
    typename T::KdfStep;
    { T::ok }              -> std::convertible_to<typename T::Status>;
    { T::err_invalid_sig } -> std::convertible_to<typename T::Status>;
    { T::err_invalid_arg } -> std::convertible_to<typename T::Status>;
    { T::null_key_id() }   -> std::same_as<typename T::KeyId>;
    { T::make_key_attrs() } -> std::same_as<typename T::KeyAttributes>;
    { T::make_kdf_op() }    -> std::same_as<typename T::KdfOperation>;
    { T::crypto_init() }                                        -> std::same_as<typename T::Status>;
    { T::generate_random(buf, len) }                            -> std::same_as<typename T::Status>;
    { T::import_key(attrs, cbuf, len, key_out) }                -> std::same_as<typename T::Status>;
    { T::generate_key(attrs, key_out) }                         -> std::same_as<typename T::Status>;
    { T::destroy_key(key) }                                     -> std::same_as<typename T::Status>;
    { T::export_key(key, buf, len, len_out) }                   -> std::same_as<typename T::Status>;
    { T::export_public_key(key, buf, len, len_out) }            -> std::same_as<typename T::Status>;
    { T::sign_message(key, alg, cbuf, len, buf, len, len_out) } -> std::same_as<typename T::Status>;
    { T::verify_message(key, alg, cbuf, len, cbuf, len) }       -> std::same_as<typename T::Status>;
    { T::mac_compute(key, alg, cbuf, len, buf, len, len_out) }  -> std::same_as<typename T::Status>;
    { T::mac_verify(key, alg, cbuf, len, cbuf, len) }           -> std::same_as<typename T::Status>;
    { T::aead_encrypt(key, alg, cbuf, len, cbuf, len, cbuf, len, buf, len, len_out) } -> std::same_as<typename T::Status>;
    { T::aead_decrypt(key, alg, cbuf, len, cbuf, len, cbuf, len, buf, len, len_out) } -> std::same_as<typename T::Status>;
    { T::asymmetric_encrypt(key, alg, cbuf, len, cbuf, len, buf, len, len_out) }      -> std::same_as<typename T::Status>;
    { T::asymmetric_decrypt(key, alg, cbuf, len, cbuf, len, buf, len, len_out) }      -> std::same_as<typename T::Status>;
    { T::raw_key_agreement(alg, key, cbuf, len, buf, len, len_out) }                  -> std::same_as<typename T::Status>;
    { T::hash_compute(alg, cbuf, len, buf, len, len_out) }                            -> std::same_as<typename T::Status>;
    { T::key_derivation_setup(op, alg) }                        -> std::same_as<typename T::Status>;
    { T::key_derivation_input_key(op, step, key) }              -> std::same_as<typename T::Status>;
    { T::key_derivation_input_bytes(op, step, cbuf, len) }      -> std::same_as<typename T::Status>;
    { T::key_derivation_output_bytes(op, buf, len) }            -> std::same_as<typename T::Status>;
    { T::key_derivation_abort(op) }                             -> std::same_as<typename T::Status>;
};


template<CryptoProvider Provider>
class PsaKeyHandle {
public:
    using KeyId = Provider::KeyId;

    PsaKeyHandle() = default;

    explicit PsaKeyHandle(const KeyId id) noexcept
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

    [[nodiscard]] auto get() const noexcept -> KeyId { return id_; }

    void reset() noexcept {
        if (valid_) {
            Provider::destroy_key(id_);
            valid_ = false;
        }
    }

private:
    KeyId id_    = Provider::null_key_id();
    bool  valid_ = false;
};
