/*
Copyright Permanence AI, 2026. All rights reserved.

*/

#pragma once

#include <cstddef>
#include <cstring>

#include "aes256_gcm.hpp"
#include "chacha20_poly1305.hpp"
#include "defs.hpp"
#include "hkdf.hpp"
#include "hmac.hpp"
#include "key_store.hpp"
#include "random.hpp"
#include "sha256.hpp"
#include "sha3.hpp"
#include "sha512.hpp"
#include "sha_variant.hpp"


// ARM AArch64 assembly/intrinsic backend.
// Phase 5: generate_key and export_key for symmetric keys, on top of
// Phase 4 (SHA-256/384/512, HMAC, AES-256-GCM, random bytes).
// Everything else returns err_invalid_arg.
//
// Target: ARMv8-A / AArch64 (Apple Silicon and compatible).
// Accelerated via ARM Crypto Extensions: AES, SHA2, SHA3, PMULL/NEON.
// See arm-asm-plan.md for the phased implementation plan.
struct ArmAsmBackend {
    using Status       = int;
    using KeyId        = unsigned int;
    using Algorithm    = unsigned int;
    using KdfOperation = arm_asm::detail::HkdfState;
    using KdfStep      = unsigned int;

    // KeyAttributes carries the symmetric key size so generate_key knows
    // how many bytes to produce.  key_bytes == 0 means "not applicable"
    // (used for algorithm types the ARM ASM backend doesn't implement).
    struct KeyAttributes {
        std::size_t key_bytes{0};
    };

    static constexpr Status ok              = 0;
    static constexpr Status err_invalid_sig = 1;
    static constexpr Status err_invalid_arg = 2;

    static KeyId null_key_id() noexcept { return 0U; }
    static KeyAttributes make_key_attrs() noexcept { return {}; }
    static KdfOperation  make_kdf_op()    noexcept { return {}; }

    static Status crypto_init()                                               { return ok; }
    static Status generate_random(CryptoByte* buf, std::size_t len) {
        arm_asm::detail::generate_random_bytes(buf, len);
        return ok;
    }
    static Status hash_compute(Algorithm alg, const CryptoByte* input, std::size_t input_len,
                               CryptoByte* output, std::size_t output_size, std::size_t* output_len)
    {
        if (alg == alg_sha(ShaVariant::Sha256)) {
            if (output_size < sha256_size_bytes) { return err_invalid_arg; }
            arm_asm::detail::sha256(input, input_len, output);
            *output_len = sha256_size_bytes;
            return ok;
        }
        if (alg == alg_sha(ShaVariant::Sha512)) {
            if (output_size < sha512_size_bytes) { return err_invalid_arg; }
            arm_asm::detail::sha512(input, input_len, output);
            *output_len = sha512_size_bytes;
            return ok;
        }
        if (alg == alg_sha(ShaVariant::Sha384)) {
            if (output_size < sha384_size_bytes) { return err_invalid_arg; }
            arm_asm::detail::sha384(input, input_len, output);
            *output_len = sha384_size_bytes;
            return ok;
        }
        if (alg == alg_sha(ShaVariant::Sha3_256)) {
            if (output_size < sha3_256_size_bytes) { return err_invalid_arg; }
            arm_asm::detail::sha3_256(input, input_len, output);
            *output_len = sha3_256_size_bytes;
            return ok;
        }
        if (alg == alg_sha(ShaVariant::Sha3_384)) {
            if (output_size < sha3_384_size_bytes) { return err_invalid_arg; }
            arm_asm::detail::sha3_384(input, input_len, output);
            *output_len = sha3_384_size_bytes;
            return ok;
        }
        if (alg == alg_sha(ShaVariant::Sha3_512)) {
            if (output_size < sha3_512_size_bytes) { return err_invalid_arg; }
            arm_asm::detail::sha3_512(input, input_len, output);
            *output_len = sha3_512_size_bytes;
            return ok;
        }
        return err_invalid_arg;
    }
    static Status import_key(const KeyAttributes* /*attrs*/, const CryptoByte* key,
                             std::size_t key_len, KeyId* id) {
        const KeyId slot = arm_asm::detail::key_store_import(key, key_len);
        if (slot == 0U) { return err_invalid_arg; }
        *id = slot;
        return ok;
    }
    static Status generate_key(const KeyAttributes* attrs, KeyId* id) {
        if (attrs == nullptr || attrs->key_bytes == 0) { return err_invalid_arg; }
        if (attrs->key_bytes > arm_asm::detail::key_store_max_bytes) { return err_invalid_arg; }
        CryptoByte buf[arm_asm::detail::key_store_max_bytes]; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
        arm_asm::detail::generate_random_bytes(buf, attrs->key_bytes);
        const KeyId slot = arm_asm::detail::key_store_import(buf, attrs->key_bytes);
        // Zeroize the stack buffer regardless of outcome.
        volatile auto* p = reinterpret_cast<volatile CryptoByte*>(buf);
        for (std::size_t i = 0; i < attrs->key_bytes; ++i) { p[i] = 0; }
        if (slot == 0U) { return err_invalid_arg; }
        *id = slot;
        return ok;
    }
    static Status destroy_key(KeyId id) {
        arm_asm::detail::key_store_destroy(id);
        return ok;
    }
    static Status export_key(KeyId id, CryptoByte* out, std::size_t size, std::size_t* len) {
        const CryptoByte* key = nullptr;
        std::size_t key_len = 0;
        if (!arm_asm::detail::key_store_get(id, &key, &key_len)) { return err_invalid_arg; }
        if (size < key_len) { return err_invalid_arg; }
        std::memcpy(out, key, key_len);
        *len = key_len;
        return ok;
    }
    static Status export_public_key(KeyId /*id*/, CryptoByte* /*out*/, std::size_t /*size*/,
                                    std::size_t* /*len*/)                     { return err_invalid_arg; }
    static Status mac_compute(  // NOLINT(readability-function-size)
                              KeyId id, Algorithm alg, // NOLINT(bugprone-easily-swappable-parameters)
                              const CryptoByte* msg, std::size_t msg_len,
                              CryptoByte* out, std::size_t out_size, std::size_t* out_len) {
        const CryptoByte* key = nullptr;
        std::size_t key_len = 0;
        if (!arm_asm::detail::key_store_get(id, &key, &key_len)) { return err_invalid_arg; }
        if (alg == alg_hmac(ShaVariant::Sha256)) {
            if (out_size < sha256_size_bytes) { return err_invalid_arg; }
            arm_asm::detail::hmac_sha256(key, key_len, msg, msg_len, out);
            *out_len = sha256_size_bytes;
            return ok;
        }
        if (alg == alg_hmac(ShaVariant::Sha512)) {
            if (out_size < sha512_size_bytes) { return err_invalid_arg; }
            arm_asm::detail::hmac_sha512(key, key_len, msg, msg_len, out);
            *out_len = sha512_size_bytes;
            return ok;
        }
        if (alg == alg_hmac(ShaVariant::Sha384)) {
            if (out_size < sha384_size_bytes) { return err_invalid_arg; }
            arm_asm::detail::hmac_sha384(key, key_len, msg, msg_len, out);
            *out_len = sha384_size_bytes;
            return ok;
        }
        if (alg == alg_hmac(ShaVariant::Sha3_256)) {
            if (out_size < sha3_256_size_bytes) { return err_invalid_arg; }
            arm_asm::detail::hmac_sha3_256(key, key_len, msg, msg_len, out);
            *out_len = sha3_256_size_bytes;
            return ok;
        }
        if (alg == alg_hmac(ShaVariant::Sha3_384)) {
            if (out_size < sha3_384_size_bytes) { return err_invalid_arg; }
            arm_asm::detail::hmac_sha3_384(key, key_len, msg, msg_len, out);
            *out_len = sha3_384_size_bytes;
            return ok;
        }
        if (alg == alg_hmac(ShaVariant::Sha3_512)) {
            if (out_size < sha3_512_size_bytes) { return err_invalid_arg; }
            arm_asm::detail::hmac_sha3_512(key, key_len, msg, msg_len, out);
            *out_len = sha3_512_size_bytes;
            return ok;
        }
        return err_invalid_arg;
    }
    static Status mac_verify(KeyId id, Algorithm alg,
                             const CryptoByte* msg, std::size_t msg_len,
                             const CryptoByte* mac, std::size_t mac_len) {
        // Compute the expected MAC then constant-time compare.
        CryptoByte expected[sha512_size_bytes]; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
        std::size_t expected_len = 0;
        const Status s = mac_compute(id, alg, msg, msg_len,
                                     expected, sizeof(expected), &expected_len); // NOLINT(cppcoreguidelines-pro-bounds-array-to-pointer-decay,hicpp-no-array-decay)
        if (s != ok) { return s; }
        if (mac_len != expected_len) { return err_invalid_sig; }
        // Constant-time comparison.
        unsigned int diff = 0;
        for (std::size_t i = 0; i < expected_len; ++i) {
            diff |= static_cast<unsigned int>(mac[i]) ^ static_cast<unsigned int>(expected[i]); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index,cppcoreguidelines-pro-bounds-pointer-arithmetic)
        }
        return diff == 0U ? ok : err_invalid_sig;
    }
    static Status aead_encrypt(  // NOLINT(readability-function-size)
                               KeyId id, Algorithm alg, // NOLINT(bugprone-easily-swappable-parameters)
                               const CryptoByte* nonce, std::size_t /*nonce_len*/,
                               const CryptoByte* aad, std::size_t aad_len,
                               const CryptoByte* pt, std::size_t pt_len,
                               CryptoByte* out, std::size_t out_size, std::size_t* out_len) {
        const CryptoByte* key = nullptr;
        std::size_t key_len = 0;
        if (!arm_asm::detail::key_store_get(id, &key, &key_len)) { return err_invalid_arg; }
        if (key_len != 32) { return err_invalid_arg; }  // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        if (alg == alg_aes_gcm()) {
            if (out_size < pt_len + arm_asm::detail::aes_gcm_tag_bytes) { return err_invalid_arg; }
            arm_asm::detail::aes256_gcm_encrypt(key, nonce, aad, aad_len, pt, pt_len, out);
            *out_len = pt_len + arm_asm::detail::aes_gcm_tag_bytes;
            return ok;
        }
        if (alg == alg_chacha20_poly1305()) {
            if (out_size < pt_len + arm_asm::detail::chacha20_poly1305_tag_bytes) { return err_invalid_arg; }
            arm_asm::detail::chacha20_poly1305_encrypt(key, nonce, aad, aad_len, pt, pt_len, out);
            *out_len = pt_len + arm_asm::detail::chacha20_poly1305_tag_bytes;
            return ok;
        }
        return err_invalid_arg;
    }
    static Status aead_decrypt(  // NOLINT(readability-function-size)
                               KeyId id, Algorithm alg, // NOLINT(bugprone-easily-swappable-parameters)
                               const CryptoByte* nonce, std::size_t /*nonce_len*/,
                               const CryptoByte* aad, std::size_t aad_len,
                               const CryptoByte* ct, std::size_t ct_len,
                               CryptoByte* out, std::size_t out_size, std::size_t* out_len) {
        const CryptoByte* key = nullptr;
        std::size_t key_len = 0;
        if (!arm_asm::detail::key_store_get(id, &key, &key_len)) { return err_invalid_arg; }
        if (key_len != 32) { return err_invalid_arg; }  // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        if (alg == alg_aes_gcm()) {
            if (ct_len < arm_asm::detail::aes_gcm_tag_bytes) { return err_invalid_arg; }
            const std::size_t pt_len = ct_len - arm_asm::detail::aes_gcm_tag_bytes;
            if (out_size < pt_len) { return err_invalid_arg; }
            if (!arm_asm::detail::aes256_gcm_decrypt(key, nonce, aad, aad_len, ct, ct_len, out)) {
                return err_invalid_sig;
            }
            *out_len = pt_len;
            return ok;
        }
        if (alg == alg_chacha20_poly1305()) {
            if (ct_len < arm_asm::detail::chacha20_poly1305_tag_bytes) { return err_invalid_arg; }
            const std::size_t pt_len = ct_len - arm_asm::detail::chacha20_poly1305_tag_bytes;
            if (out_size < pt_len) { return err_invalid_arg; }
            if (!arm_asm::detail::chacha20_poly1305_decrypt(key, nonce, aad, aad_len, ct, ct_len, out)) {
                return err_invalid_sig;
            }
            *out_len = pt_len;
            return ok;
        }
        return err_invalid_arg;
    }
    static Status sign_message(  // NOLINT(readability-function-size)
                               KeyId /*id*/, Algorithm /*alg*/,
                               const CryptoByte* /*msg*/, std::size_t /*msg_len*/,
                               CryptoByte* /*sig*/, std::size_t /*sig_size*/, std::size_t* /*sig_len*/)
                                                                              { return err_invalid_arg; }
    static Status verify_message(KeyId /*id*/, Algorithm /*alg*/,
                                 const CryptoByte* /*msg*/, std::size_t /*msg_len*/,
                                 const CryptoByte* /*sig*/, std::size_t /*sig_len*/)
                                                                              { return err_invalid_arg; }
    static Status raw_key_agreement(  // NOLINT(readability-function-size)
                                    Algorithm /*alg*/, KeyId /*id*/,
                                    const CryptoByte* /*peer*/, std::size_t /*peer_len*/,
                                    CryptoByte* /*out*/, std::size_t /*out_size*/, std::size_t* /*out_len*/)
                                                                              { return err_invalid_arg; }
    static Status asymmetric_encrypt(  // NOLINT(readability-function-size)
                                     KeyId /*id*/, Algorithm /*alg*/,
                                     const CryptoByte* /*pt*/, std::size_t /*pt_len*/,
                                     const CryptoByte* /*salt*/, std::size_t /*salt_len*/,
                                     CryptoByte* /*out*/, std::size_t /*out_size*/, std::size_t* /*out_len*/)
                                                                              { return err_invalid_arg; }
    static Status asymmetric_decrypt(  // NOLINT(readability-function-size)
                                     KeyId /*id*/, Algorithm /*alg*/,
                                     const CryptoByte* /*ct*/, std::size_t /*ct_len*/,
                                     const CryptoByte* /*salt*/, std::size_t /*salt_len*/,
                                     CryptoByte* /*out*/, std::size_t /*out_size*/, std::size_t* /*out_len*/)
                                                                              { return err_invalid_arg; }
    static Status key_derivation_setup(KdfOperation* op, Algorithm alg) {
        arm_asm::detail::HkdfAlg ha = arm_asm::detail::HkdfAlg::None;
        if (alg == alg_hkdf())        { ha = arm_asm::detail::HkdfAlg::Hkdf; }
        else if (alg == alg_hkdf_expand()) { ha = arm_asm::detail::HkdfAlg::HkdfExpand; }
        else { return err_invalid_arg; }
        return arm_asm::detail::hkdf_setup(op, ha) == 0 ? ok : err_invalid_arg;
    }
    static Status key_derivation_input_key(KdfOperation* op, KdfStep /*step*/, KeyId id) {
        return arm_asm::detail::hkdf_input_key(op, id) == 0 ? ok : err_invalid_arg;
    }
    static Status key_derivation_input_bytes(KdfOperation* op, KdfStep step,
                                             const CryptoByte* data, std::size_t len) {
        return arm_asm::detail::hkdf_input_bytes(op, step, data, len) == 0 ? ok : err_invalid_arg;
    }
    static Status key_derivation_output_bytes(KdfOperation* op, CryptoByte* out, std::size_t len) {
        return arm_asm::detail::hkdf_output_bytes(op, out, len) == 0 ? ok : err_invalid_arg;
    }
    static Status key_derivation_abort(KdfOperation* op) {
        if (op != nullptr) { op->zeroize(); }
        return ok;
    }

    // Algorithm tag encoding: low byte = base type, high byte = SHA variant index.
    static constexpr Algorithm alg_base_hash = 0x0100U;
    static constexpr Algorithm alg_base_hmac = 0x0200U;

    static Algorithm alg_sha(ShaVariant v)  noexcept { return alg_base_hash | static_cast<Algorithm>(v); }
    static Algorithm alg_hmac(ShaVariant v) noexcept { return alg_base_hmac | static_cast<Algorithm>(v); }
    static constexpr Algorithm alg_ecdsa()             noexcept { return 0U; }
    static constexpr Algorithm alg_ecdh()              noexcept { return 0U; }
    static constexpr Algorithm alg_hkdf()              noexcept { return 0x0301U; }
    static constexpr Algorithm alg_hkdf_expand()       noexcept { return 0x0302U; }
    static constexpr Algorithm alg_aes_gcm()           noexcept { return 0x0401U; }
    static constexpr Algorithm alg_chacha20_poly1305() noexcept { return 0x0402U; }
    static constexpr Algorithm alg_rsa_oaep()          noexcept { return 0U; }
    static constexpr Algorithm alg_rsa_pss()           noexcept { return 0U; }

    // kdf_step_secret is ignored (key is implicitly the IKM/PRK from input_key).
    // kdf_step_salt and kdf_step_info match the constants in hkdf_input_bytes.
    static constexpr KdfStep kdf_step_secret() noexcept { return 2U; }
    static constexpr KdfStep kdf_step_salt()   noexcept { return 0U; }
    static constexpr KdfStep kdf_step_info()   noexcept { return 1U; }

    // NOLINT(readability-named-parameter) — stub functions intentionally omit unused parameter names.
    static KeyAttributes make_hkdf_derive_attrs(std::size_t bits)              noexcept { return {bits / 8U}; }
    static KeyAttributes make_hkdf_expand_derive_attrs(std::size_t bits)       noexcept { return {bits / 8U}; }
    static KeyAttributes make_hmac_generate_attrs(ShaVariant /*v*/, std::size_t bits) noexcept { return {bits / 8U}; }
    static KeyAttributes make_hmac_verify_attrs(ShaVariant /*v*/, std::size_t bits)   noexcept { return {bits / 8U}; }
    static KeyAttributes make_ecdsa_generate_attrs(std::size_t /*bits*/)       noexcept { return {}; }
    static KeyAttributes make_ecdsa_sign_attrs(std::size_t /*bits*/)           noexcept { return {}; }
    static KeyAttributes make_ecdsa_verify_attrs(std::size_t /*bits*/)         noexcept { return {}; }
    static KeyAttributes make_ecdh_generate_attrs(std::size_t /*bits*/)        noexcept { return {}; }
    static KeyAttributes make_ecdh_agree_attrs(std::size_t /*bits*/)           noexcept { return {}; }
    static KeyAttributes make_aes256_gcm_encrypt_attrs()                       noexcept { return {aes256_key_size_bytes}; }
    static KeyAttributes make_aes256_gcm_decrypt_attrs()                       noexcept { return {aes256_key_size_bytes}; }
    static KeyAttributes make_chacha20_poly1305_encrypt_attrs()                noexcept { return {chacha20_key_size_bytes}; }
    static KeyAttributes make_chacha20_poly1305_decrypt_attrs()                noexcept { return {chacha20_key_size_bytes}; }
    static KeyAttributes make_rsa_oaep_encrypt_attrs(std::size_t /*bits*/)     noexcept { return {}; }
    static KeyAttributes make_rsa_oaep_decrypt_attrs(std::size_t /*bits*/)     noexcept { return {}; }
    static KeyAttributes make_rsa_pss_sign_attrs(std::size_t /*bits*/)         noexcept { return {}; }
    static KeyAttributes make_rsa_pss_verify_attrs(std::size_t /*bits*/)       noexcept { return {}; }
    static KeyAttributes make_rsa_key_pair_attrs(std::size_t /*bits*/)         noexcept { return {}; }

    static std::size_t ecdsa_sign_output_size(std::size_t /*bits*/)          noexcept { return 0; }
    static std::size_t ecdh_shared_secret_size(std::size_t /*bits*/)         noexcept { return 0; }
    static std::size_t ec_private_key_export_size(std::size_t /*bits*/)      noexcept { return 0; }
    static std::size_t ec_public_key_export_size(std::size_t /*bits*/)       noexcept { return 0; }
    static std::size_t aes_gcm_encrypt_output_size(std::size_t pt_len)        noexcept { return pt_len + arm_asm::detail::aes_gcm_tag_bytes; }
    static std::size_t aes_gcm_decrypt_output_size(std::size_t ct_len)        noexcept { return ct_len > arm_asm::detail::aes_gcm_tag_bytes ? ct_len - arm_asm::detail::aes_gcm_tag_bytes : 0; }
    static std::size_t chacha20_encrypt_output_size(std::size_t pt_len) noexcept { return pt_len + arm_asm::detail::chacha20_poly1305_tag_bytes; }
    static std::size_t chacha20_decrypt_output_size(std::size_t ct_len) noexcept { return ct_len > arm_asm::detail::chacha20_poly1305_tag_bytes ? ct_len - arm_asm::detail::chacha20_poly1305_tag_bytes : 0; }
    static std::size_t rsa_oaep_encrypt_output_size(std::size_t /*bits*/)    noexcept { return 0; }
    static std::size_t rsa_oaep_decrypt_output_size(std::size_t /*bits*/)    noexcept { return 0; }
    static std::size_t rsa_pss_sign_output_size(std::size_t /*bits*/)        noexcept { return 0; }
    static std::size_t rsa_private_key_export_size(std::size_t /*bits*/)     noexcept { return 0; }
    static std::size_t rsa_public_key_export_size(std::size_t /*bits*/)      noexcept { return 0; }
};
