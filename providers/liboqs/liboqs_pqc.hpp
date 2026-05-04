/*
Copyright Permanence AI, 2026. All rights reserved.

*/

#pragma once

// Thin C++ wrappers around liboqs OQS_KEM and OQS_SIG for ML-KEM and ML-DSA.
// All functions operate on raw CryptoByte* buffers and return a bool
// (true = success).  The caller owns all buffers; no heap allocation here.

#include <cstddef>
#include <cstring>

#include <oqs/oqs.h>

#include "defs.hpp"
#include "ml_dsa_variant.hpp"
#include "ml_kem_variant.hpp"

namespace liboqs_pqc {

// Returns the OQS algorithm name string for a MlKemVariant.
[[nodiscard]]
constexpr const char* ml_kem_alg_name(const MlKemVariant v) noexcept {
    switch (v) {
        case MlKemVariant::Kem512:  return OQS_KEM_alg_ml_kem_512;
        case MlKemVariant::Kem768:  return OQS_KEM_alg_ml_kem_768;
        case MlKemVariant::Kem1024: return OQS_KEM_alg_ml_kem_1024;
    }
}

// Returns the OQS algorithm name string for a MlDsaVariant.
[[nodiscard]]
constexpr const char* ml_dsa_alg_name(const MlDsaVariant v) noexcept {
    switch (v) {
        case MlDsaVariant::Dsa44: return OQS_SIG_alg_ml_dsa_44;
        case MlDsaVariant::Dsa65: return OQS_SIG_alg_ml_dsa_65;
        case MlDsaVariant::Dsa87: return OQS_SIG_alg_ml_dsa_87;
    }
}

// --- ML-KEM ---

[[nodiscard]]
inline bool ml_kem_keygen(
    const MlKemVariant variant,
    CryptoByte* public_key,  std::size_t public_key_size,
    CryptoByte* private_key, std::size_t private_key_size) noexcept
{
    OQS_KEM* kem = OQS_KEM_new(ml_kem_alg_name(variant));
    if (kem == nullptr) { return false; }
    if (public_key_size  < kem->length_public_key ||
        private_key_size < kem->length_secret_key) {
        OQS_KEM_free(kem);
        return false;
    }
    const bool ok = OQS_KEM_keypair(kem, public_key, private_key) == OQS_SUCCESS;
    OQS_KEM_free(kem);
    return ok;
}

[[nodiscard]]
inline bool ml_kem_encaps(
    const MlKemVariant variant,
    const CryptoByte* public_key, std::size_t public_key_size,
    CryptoByte* ciphertext,    std::size_t ciphertext_size,
    CryptoByte* shared_secret, std::size_t shared_secret_size) noexcept
{
    OQS_KEM* kem = OQS_KEM_new(ml_kem_alg_name(variant));
    if (kem == nullptr) { return false; }
    if (public_key_size   < kem->length_public_key  ||
        ciphertext_size   < kem->length_ciphertext  ||
        shared_secret_size < kem->length_shared_secret) {
        OQS_KEM_free(kem);
        return false;
    }
    (void)public_key_size;  // size already checked above
    const bool ok = OQS_KEM_encaps(kem, ciphertext, shared_secret, public_key) == OQS_SUCCESS;
    OQS_KEM_free(kem);
    return ok;
}

[[nodiscard]]
inline bool ml_kem_decaps(
    const MlKemVariant variant,
    const CryptoByte* private_key,  std::size_t private_key_size,
    const CryptoByte* ciphertext,   std::size_t ciphertext_size,
    CryptoByte*       shared_secret, std::size_t shared_secret_size) noexcept
{
    OQS_KEM* kem = OQS_KEM_new(ml_kem_alg_name(variant));
    if (kem == nullptr) { return false; }
    if (private_key_size   < kem->length_secret_key     ||
        ciphertext_size    < kem->length_ciphertext     ||
        shared_secret_size < kem->length_shared_secret) {
        OQS_KEM_free(kem);
        return false;
    }
    (void)private_key_size;
    (void)ciphertext_size;
    const bool ok = OQS_KEM_decaps(kem, shared_secret, ciphertext, private_key) == OQS_SUCCESS;
    OQS_KEM_free(kem);
    return ok;
}

// --- ML-DSA ---

[[nodiscard]]
inline bool ml_dsa_keygen(
    const MlDsaVariant variant,
    CryptoByte* public_key,  std::size_t public_key_size,
    CryptoByte* private_key, std::size_t private_key_size) noexcept
{
    OQS_SIG* sig = OQS_SIG_new(ml_dsa_alg_name(variant));
    if (sig == nullptr) { return false; }
    if (public_key_size  < sig->length_public_key ||
        private_key_size < sig->length_secret_key) {
        OQS_SIG_free(sig);
        return false;
    }
    const bool ok = OQS_SIG_keypair(sig, public_key, private_key) == OQS_SUCCESS;
    OQS_SIG_free(sig);
    return ok;
}

[[nodiscard]]
inline bool ml_dsa_sign(
    const MlDsaVariant variant,
    const CryptoByte* private_key,  std::size_t private_key_size,
    const CryptoByte* message,      std::size_t message_size,
    CryptoByte*       signature,    std::size_t signature_size,
    std::size_t*      signature_len) noexcept
{
    OQS_SIG* sig = OQS_SIG_new(ml_dsa_alg_name(variant));
    if (sig == nullptr) { return false; }
    if (private_key_size < sig->length_secret_key ||
        signature_size   < sig->length_signature) {
        OQS_SIG_free(sig);
        return false;
    }
    (void)private_key_size;
    const bool ok = OQS_SIG_sign(sig, signature, signature_len,
                                  message, message_size,
                                  private_key) == OQS_SUCCESS;
    OQS_SIG_free(sig);
    return ok;
}

[[nodiscard]]
inline bool ml_dsa_verify(
    const MlDsaVariant variant,
    const CryptoByte* public_key,  std::size_t public_key_size,
    const CryptoByte* message,     std::size_t message_size,
    const CryptoByte* signature,   std::size_t signature_len) noexcept
{
    OQS_SIG* sig = OQS_SIG_new(ml_dsa_alg_name(variant));
    if (sig == nullptr) { return false; }
    if (public_key_size < sig->length_public_key) {
        OQS_SIG_free(sig);
        return false;
    }
    (void)public_key_size;
    const bool ok = OQS_SIG_verify(sig, message, message_size,
                                    signature, signature_len,
                                    public_key) == OQS_SUCCESS;
    OQS_SIG_free(sig);
    return ok;
}

}  // namespace liboqs_pqc
