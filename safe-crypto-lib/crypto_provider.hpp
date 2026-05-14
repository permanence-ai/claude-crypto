// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <concepts>
#include <cstddef>
#include <expected>

#include "contracts.hpp"
#include "defs.hpp"
#include "ml_dsa_variant.hpp"
#include "ml_kem_variant.hpp"
#include "sha_variant.hpp"
#include "slh_dsa_variant.hpp"


// Concept satisfied by any CryptoProvider implementation.  Providers expose:
//   - Associated types: Status, KeyId, Algorithm, KeyAttributes, KdfOperation, KdfStep
//   - Status sentinels: ok, err_invalid_sig, err_invalid_arg
//   - Low-level object factories: null_key_id, make_key_attrs, make_kdf_op
//   - Algorithm constants: alg_sha, alg_hmac, alg_ecdsa, alg_ecdh, alg_hkdf,
//     alg_hkdf_expand, alg_aes_gcm, alg_chacha20_poly1305, alg_rsa_oaep, alg_rsa_pss
//   - KDF step constants: kdf_step_secret, kdf_step_salt, kdf_step_info
//   - Key attribute factories: make_hkdf_derive_attrs, make_ecdsa_sign_attrs, etc.
//   - Output size helpers: ecdsa_sign_output_size, aes_gcm_encrypt_output_size, etc.
//   - Low-level crypto operations: import_key, generate_key, sign_message, etc.
//
// _impl bodies use only these provider-neutral names — no PSA/MbedTLS types or
// macros appear outside the provider structs.  A future OpenSSL or ASM provider
// supplies its own aliases and wrappers behind this same interface.
template<typename T>
concept CryptoProvider = requires(
    T,
    T::KeyAttributes*  attrs,
    T::KeyId           key,
    T::Algorithm       alg,
    T::KdfStep         step,
    T::KdfOperation*   op,
    CryptoByte*        buf,
    const CryptoByte*  cbuf,
    std::size_t        len,
    std::size_t*       len_out,
    ShaVariant         sha_v,
    SlhDsaVariant      slh_v,
    MlDsaVariant       ml_v,
    MlKemVariant       kem_v)
{
    // Associated types
    typename T::Status;
    typename T::KeyId;
    typename T::Algorithm;
    typename T::KeyAttributes;
    typename T::KdfOperation;
    typename T::KdfStep;
    // Status sentinels
    { T::ok }              -> std::convertible_to<typename T::Status>;
    { T::err_invalid_sig } -> std::convertible_to<typename T::Status>;
    { T::err_invalid_arg } -> std::convertible_to<typename T::Status>;
    // Low-level object factories
    { T::null_key_id() }    -> std::same_as<typename T::KeyId>;
    { T::make_key_attrs() } -> std::same_as<typename T::KeyAttributes>;
    { T::make_kdf_op() }    -> std::same_as<typename T::KdfOperation>;
    // Algorithm constants
    { T::alg_sha(sha_v) }              -> std::same_as<typename T::Algorithm>;
    { T::alg_hmac(sha_v) }             -> std::same_as<typename T::Algorithm>;
    { T::alg_ecdsa() }                 -> std::same_as<typename T::Algorithm>;
    { T::alg_ecdh() }                  -> std::same_as<typename T::Algorithm>;
    { T::alg_hkdf() }                  -> std::same_as<typename T::Algorithm>;
    { T::alg_hkdf_expand() }           -> std::same_as<typename T::Algorithm>;
    { T::alg_aes_gcm() }               -> std::same_as<typename T::Algorithm>;
    { T::alg_chacha20_poly1305() }     -> std::same_as<typename T::Algorithm>;
    { T::alg_rsa_oaep() }              -> std::same_as<typename T::Algorithm>;
    { T::alg_rsa_pss() }               -> std::same_as<typename T::Algorithm>;
    { T::alg_slh_dsa(slh_v) }         -> std::same_as<typename T::Algorithm>;
    { T::alg_ml_dsa(ml_v) }           -> std::same_as<typename T::Algorithm>;
    { T::alg_ml_kem(kem_v) }          -> std::same_as<typename T::Algorithm>;
    // KDF step constants
    { T::kdf_step_secret() } -> std::same_as<typename T::KdfStep>;
    { T::kdf_step_salt() }   -> std::same_as<typename T::KdfStep>;
    { T::kdf_step_info() }   -> std::same_as<typename T::KdfStep>;
    // Key attribute factories
    { T::make_hkdf_derive_attrs(len) }           -> std::same_as<typename T::KeyAttributes>;
    { T::make_hkdf_expand_derive_attrs(len) }    -> std::same_as<typename T::KeyAttributes>;
    { T::make_hmac_generate_attrs(sha_v, len) }  -> std::same_as<typename T::KeyAttributes>;
    { T::make_hmac_verify_attrs(sha_v, len) }    -> std::same_as<typename T::KeyAttributes>;
    { T::make_ecdsa_generate_attrs(len) }        -> std::same_as<typename T::KeyAttributes>;
    { T::make_ecdsa_sign_attrs(len) }            -> std::same_as<typename T::KeyAttributes>;
    { T::make_ecdsa_verify_attrs(len) }          -> std::same_as<typename T::KeyAttributes>;
    { T::make_ecdh_generate_attrs(len) }         -> std::same_as<typename T::KeyAttributes>;
    { T::make_ecdh_agree_attrs(len) }            -> std::same_as<typename T::KeyAttributes>;
    { T::make_aes256_gcm_encrypt_attrs() }       -> std::same_as<typename T::KeyAttributes>;
    { T::make_aes256_gcm_decrypt_attrs() }       -> std::same_as<typename T::KeyAttributes>;
    { T::make_chacha20_poly1305_encrypt_attrs() } -> std::same_as<typename T::KeyAttributes>;
    { T::make_chacha20_poly1305_decrypt_attrs() } -> std::same_as<typename T::KeyAttributes>;
    { T::make_rsa_oaep_encrypt_attrs(len) }      -> std::same_as<typename T::KeyAttributes>;
    { T::make_rsa_oaep_decrypt_attrs(len) }      -> std::same_as<typename T::KeyAttributes>;
    { T::make_rsa_pss_sign_attrs(len) }          -> std::same_as<typename T::KeyAttributes>;
    { T::make_rsa_pss_verify_attrs(len) }        -> std::same_as<typename T::KeyAttributes>;
    { T::make_rsa_key_pair_attrs(len) }          -> std::same_as<typename T::KeyAttributes>;
    { T::make_slh_dsa_sign_attrs(slh_v) }       -> std::same_as<typename T::KeyAttributes>;
    { T::make_slh_dsa_verify_attrs(slh_v) }     -> std::same_as<typename T::KeyAttributes>;
    { T::make_slh_dsa_generate_attrs(slh_v) }   -> std::same_as<typename T::KeyAttributes>;
    { T::make_ml_dsa_sign_attrs(ml_v) }         -> std::same_as<typename T::KeyAttributes>;
    { T::make_ml_dsa_verify_attrs(ml_v) }       -> std::same_as<typename T::KeyAttributes>;
    { T::make_ml_dsa_generate_attrs(ml_v) }     -> std::same_as<typename T::KeyAttributes>;
    { T::make_ml_kem_generate_attrs(kem_v) }    -> std::same_as<typename T::KeyAttributes>;
    { T::make_ml_kem_encap_attrs(kem_v) }       -> std::same_as<typename T::KeyAttributes>;
    { T::make_ml_kem_decap_attrs(kem_v) }       -> std::same_as<typename T::KeyAttributes>;
    // Output size helpers
    { T::ecdsa_sign_output_size(len) }           -> std::same_as<std::size_t>;
    { T::ecdh_shared_secret_size(len) }          -> std::same_as<std::size_t>;
    { T::ec_private_key_export_size(len) }       -> std::same_as<std::size_t>;
    { T::ec_public_key_export_size(len) }        -> std::same_as<std::size_t>;
    { T::aes_gcm_encrypt_output_size(len) }      -> std::same_as<std::size_t>;
    { T::aes_gcm_decrypt_output_size(len) }      -> std::same_as<std::size_t>;
    { T::chacha20_encrypt_output_size(len) }     -> std::same_as<std::size_t>;
    { T::chacha20_decrypt_output_size(len) }     -> std::same_as<std::size_t>;
    { T::rsa_oaep_encrypt_output_size(len) }     -> std::same_as<std::size_t>;
    { T::rsa_oaep_decrypt_output_size(len) }     -> std::same_as<std::size_t>;
    { T::rsa_pss_sign_output_size(len) }         -> std::same_as<std::size_t>;
    { T::rsa_private_key_export_size(len) }      -> std::same_as<std::size_t>;
    { T::rsa_public_key_export_size(len) }       -> std::same_as<std::size_t>;
    { T::slh_dsa_sign_output_size(slh_v) }        -> std::same_as<std::size_t>;
    { T::slh_dsa_private_key_export_size(slh_v) } -> std::same_as<std::size_t>;
    { T::slh_dsa_public_key_export_size(slh_v) }  -> std::same_as<std::size_t>;
    { T::ml_dsa_sign_output_size(ml_v) }          -> std::same_as<std::size_t>;
    { T::ml_dsa_private_key_export_size(ml_v) }   -> std::same_as<std::size_t>;
    { T::ml_dsa_public_key_export_size(ml_v) }    -> std::same_as<std::size_t>;
    { T::ml_kem_ciphertext_size(kem_v) }           -> std::same_as<std::size_t>;
    { T::ml_kem_shared_secret_size(kem_v) }        -> std::same_as<std::size_t>;
    { T::ml_kem_private_key_export_size(kem_v) }   -> std::same_as<std::size_t>;
    { T::ml_kem_public_key_export_size(kem_v) }    -> std::same_as<std::size_t>;
    // Low-level crypto operations
    { T::crypto_init() }                                        -> std::same_as<typename T::Status>;
    { T::generate_random(buf, len) }                            -> std::same_as<typename T::Status>;
    { T::import_key(attrs, cbuf, len) }  -> std::same_as<std::expected<typename T::KeyId, typename T::Status>>;
    { T::generate_key(attrs) }           -> std::same_as<std::expected<typename T::KeyId, typename T::Status>>;
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
    { T::kem_encapsulate(key, alg, buf, len, len_out, buf, len, len_out) }            -> std::same_as<typename T::Status>;
    { T::kem_decapsulate(key, alg, cbuf, len, buf, len, len_out) }                    -> std::same_as<typename T::Status>;
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
            (void)Provider::destroy_key(id_);
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

    [[nodiscard]] auto get() const noexcept SAFE_CRYPTO_PRE(valid_) -> KeyId { return id_; }

    void reset() noexcept {
        if (valid_) {
            (void)Provider::destroy_key(id_);
            valid_ = false;
        }
    }

private:
    KeyId id_    = Provider::null_key_id();
    bool  valid_ = false;
};
