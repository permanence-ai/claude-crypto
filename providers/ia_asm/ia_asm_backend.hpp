/*
Copyright Permanence AI, 2026. All rights reserved.

*/

#pragma once

#include <cstddef>

#include "defs.hpp"
#include "sha_variant.hpp"


// Stub backend for the IA assembly provider.  Not yet implemented — every
// operation returns a generic failure status so the library link targets exist
// and the concept is satisfied at compile time.
struct IaAsmBackend {
    using Status        = int;
    using KeyId         = unsigned int;
    using Algorithm     = unsigned int;
    using KeyAttributes = unsigned int;
    using KdfOperation  = unsigned int;
    using KdfStep       = unsigned int;

    static constexpr Status ok              = 0;
    static constexpr Status err_invalid_sig = 1;
    static constexpr Status err_invalid_arg = 2;

    static KeyId null_key_id() noexcept { return 0U; }
    static KeyAttributes make_key_attrs() noexcept { return 0U; }
    static KdfOperation  make_kdf_op()    noexcept { return 0U; }

    static Status crypto_init()                                               { return ok; }
    static Status generate_random(CryptoByte*, std::size_t)                   { return err_invalid_arg; }
    static Status hash_compute(Algorithm, const CryptoByte*, std::size_t,
                               CryptoByte*, std::size_t, std::size_t*)        { return err_invalid_arg; }
    static Status import_key(const KeyAttributes*, const CryptoByte*,
                             std::size_t, KeyId*)                             { return err_invalid_arg; }
    static Status generate_key(const KeyAttributes*, KeyId*)                  { return err_invalid_arg; }
    static Status destroy_key(KeyId)                                          { return err_invalid_arg; }
    static Status export_key(KeyId, CryptoByte*, std::size_t, std::size_t*)   { return err_invalid_arg; }
    static Status export_public_key(KeyId, CryptoByte*, std::size_t,
                                    std::size_t*)                             { return err_invalid_arg; }
    static Status mac_compute(KeyId, Algorithm, const CryptoByte*, std::size_t,  // NOLINT(readability-function-size)
                              CryptoByte*, std::size_t, std::size_t*)         { return err_invalid_arg; }
    static Status mac_verify(KeyId, Algorithm, const CryptoByte*, std::size_t,
                             const CryptoByte*, std::size_t)                  { return err_invalid_arg; }
    static Status aead_encrypt(KeyId, Algorithm,  // NOLINT(readability-function-size)
                               const CryptoByte*, std::size_t,
                               const CryptoByte*, std::size_t,
                               const CryptoByte*, std::size_t,
                               CryptoByte*, std::size_t, std::size_t*)        { return err_invalid_arg; }
    static Status aead_decrypt(KeyId, Algorithm,  // NOLINT(readability-function-size)
                               const CryptoByte*, std::size_t,
                               const CryptoByte*, std::size_t,
                               const CryptoByte*, std::size_t,
                               CryptoByte*, std::size_t, std::size_t*)        { return err_invalid_arg; }
    static Status sign_message(KeyId, Algorithm,  // NOLINT(readability-function-size)
                               const CryptoByte*, std::size_t,
                               CryptoByte*, std::size_t, std::size_t*)        { return err_invalid_arg; }
    static Status verify_message(KeyId, Algorithm,
                                 const CryptoByte*, std::size_t,
                                 const CryptoByte*, std::size_t)              { return err_invalid_arg; }
    static Status raw_key_agreement(Algorithm, KeyId,  // NOLINT(readability-function-size)
                                    const CryptoByte*, std::size_t,
                                    CryptoByte*, std::size_t, std::size_t*)   { return err_invalid_arg; }
    static Status asymmetric_encrypt(KeyId, Algorithm,  // NOLINT(readability-function-size)
                                     const CryptoByte*, std::size_t,
                                     const CryptoByte*, std::size_t,
                                     CryptoByte*, std::size_t, std::size_t*)  { return err_invalid_arg; }
    static Status asymmetric_decrypt(KeyId, Algorithm,  // NOLINT(readability-function-size)
                                     const CryptoByte*, std::size_t,
                                     const CryptoByte*, std::size_t,
                                     CryptoByte*, std::size_t, std::size_t*)  { return err_invalid_arg; }
    static Status key_derivation_setup(KdfOperation*, Algorithm)              { return err_invalid_arg; }
    static Status key_derivation_input_key(KdfOperation*, KdfStep, KeyId)     { return err_invalid_arg; }
    static Status key_derivation_input_bytes(KdfOperation*, KdfStep,
                                             const CryptoByte*, std::size_t)  { return err_invalid_arg; }
    static Status key_derivation_output_bytes(KdfOperation*,
                                              CryptoByte*, std::size_t)       { return err_invalid_arg; }
    static Status key_derivation_abort(KdfOperation*)                         { return ok; }

    static Algorithm alg_sha(ShaVariant)       noexcept { return 0U; }
    static Algorithm alg_hmac(ShaVariant)      noexcept { return 0U; }
    static constexpr Algorithm alg_ecdsa()              noexcept { return 0U; }
    static constexpr Algorithm alg_ecdh()               noexcept { return 0U; }
    static constexpr Algorithm alg_hkdf()               noexcept { return 0U; }
    static constexpr Algorithm alg_hkdf_expand()        noexcept { return 0U; }
    static constexpr Algorithm alg_aes_gcm()            noexcept { return 0U; }
    static constexpr Algorithm alg_chacha20_poly1305()  noexcept { return 0U; }
    static constexpr Algorithm alg_rsa_oaep()           noexcept { return 0U; }
    static constexpr Algorithm alg_rsa_pss()            noexcept { return 0U; }

    static constexpr KdfStep kdf_step_secret() noexcept { return 0U; }
    static constexpr KdfStep kdf_step_salt()   noexcept { return 0U; }
    static constexpr KdfStep kdf_step_info()   noexcept { return 0U; }

    static KeyAttributes make_hkdf_derive_attrs(std::size_t)          noexcept { return 0U; }
    static KeyAttributes make_hkdf_expand_derive_attrs(std::size_t)   noexcept { return 0U; }
    static KeyAttributes make_hmac_generate_attrs(ShaVariant, std::size_t) noexcept { return 0U; }
    static KeyAttributes make_hmac_verify_attrs(ShaVariant, std::size_t)   noexcept { return 0U; }
    static KeyAttributes make_ecdsa_generate_attrs(std::size_t)       noexcept { return 0U; }
    static KeyAttributes make_ecdsa_sign_attrs(std::size_t)           noexcept { return 0U; }
    static KeyAttributes make_ecdsa_verify_attrs(std::size_t)         noexcept { return 0U; }
    static KeyAttributes make_ecdh_generate_attrs(std::size_t)        noexcept { return 0U; }
    static KeyAttributes make_ecdh_agree_attrs(std::size_t)           noexcept { return 0U; }
    static KeyAttributes make_aes256_gcm_encrypt_attrs()              noexcept { return 0U; }
    static KeyAttributes make_aes256_gcm_decrypt_attrs()              noexcept { return 0U; }
    static KeyAttributes make_chacha20_poly1305_encrypt_attrs()       noexcept { return 0U; }
    static KeyAttributes make_chacha20_poly1305_decrypt_attrs()       noexcept { return 0U; }
    static KeyAttributes make_rsa_oaep_encrypt_attrs(std::size_t)     noexcept { return 0U; }
    static KeyAttributes make_rsa_oaep_decrypt_attrs(std::size_t)     noexcept { return 0U; }
    static KeyAttributes make_rsa_pss_sign_attrs(std::size_t)         noexcept { return 0U; }
    static KeyAttributes make_rsa_pss_verify_attrs(std::size_t)       noexcept { return 0U; }
    static KeyAttributes make_rsa_key_pair_attrs(std::size_t)         noexcept { return 0U; }

    static std::size_t ecdsa_sign_output_size(std::size_t)          noexcept { return 0; }
    static std::size_t ecdh_shared_secret_size(std::size_t)         noexcept { return 0; }
    static std::size_t ec_private_key_export_size(std::size_t)      noexcept { return 0; }
    static std::size_t ec_public_key_export_size(std::size_t)       noexcept { return 0; }
    static std::size_t aes_gcm_encrypt_output_size(std::size_t)     noexcept { return 0; }
    static std::size_t aes_gcm_decrypt_output_size(std::size_t)     noexcept { return 0; }
    static std::size_t chacha20_encrypt_output_size(std::size_t)    noexcept { return 0; }
    static std::size_t chacha20_decrypt_output_size(std::size_t)    noexcept { return 0; }
    static std::size_t rsa_oaep_encrypt_output_size(std::size_t)    noexcept { return 0; }
    static std::size_t rsa_oaep_decrypt_output_size(std::size_t)    noexcept { return 0; }
    static std::size_t rsa_pss_sign_output_size(std::size_t)        noexcept { return 0; }
    static std::size_t rsa_private_key_export_size(std::size_t)     noexcept { return 0; }
    static std::size_t rsa_public_key_export_size(std::size_t)      noexcept { return 0; }
};
