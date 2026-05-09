// SPDX-License-Identifier: Apache-2.0

#pragma once

// Thin C++ wrappers around liboqs OQS_KEM and OQS_SIG for ML-KEM and ML-DSA.
// All functions operate on raw CryptoByte* buffers and return a bool
// (true = success).  The caller owns all buffers; no heap allocation here.
//
// OQS_KEM and OQS_SIG objects are allocated once per variant and cached in
// function-local statics (C++11 guarantees thread-safe first-call initialisation).
// All OQS_KEM_*/OQS_SIG_* operation functions take a const pointer, so the same
// object is safely shared across concurrent callers without any additional locking.

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

namespace detail {

// Per-variant cached OQS_KEM*.  Allocated once on first use; never freed
// (intentional: program lifetime).  Thread-safe per C++11 § 6.7 [stmt.dcl].
[[nodiscard]]
inline const OQS_KEM* kem_for(const MlKemVariant v) noexcept {
    switch (v) {
        case MlKemVariant::Kem512: {
            static const OQS_KEM* const inst = OQS_KEM_new(OQS_KEM_alg_ml_kem_512);
            return inst;
        }
        case MlKemVariant::Kem768: {
            static const OQS_KEM* const inst = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
            return inst;
        }
        case MlKemVariant::Kem1024: {
            static const OQS_KEM* const inst = OQS_KEM_new(OQS_KEM_alg_ml_kem_1024);
            return inst;
        }
    }
}

// Per-variant cached OQS_SIG*.  Same lifetime policy as kem_for.
[[nodiscard]]
inline const OQS_SIG* sig_for(const MlDsaVariant v) noexcept {
    switch (v) {
        case MlDsaVariant::Dsa44: {
            static const OQS_SIG* const inst = OQS_SIG_new(OQS_SIG_alg_ml_dsa_44);
            return inst;
        }
        case MlDsaVariant::Dsa65: {
            static const OQS_SIG* const inst = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
            return inst;
        }
        case MlDsaVariant::Dsa87: {
            static const OQS_SIG* const inst = OQS_SIG_new(OQS_SIG_alg_ml_dsa_87);
            return inst;
        }
    }
}

}  // namespace detail


// --- ML-KEM ---

[[nodiscard]]
inline bool ml_kem_keygen(
    const MlKemVariant variant,
    CryptoByte* public_key,  std::size_t public_key_size,
    CryptoByte* private_key, std::size_t private_key_size) noexcept
{
    const OQS_KEM* kem = detail::kem_for(variant);
    if (kem == nullptr) { return false; }
    if (public_key_size  < kem->length_public_key ||
        private_key_size < kem->length_secret_key) {
        return false;
    }
    return OQS_KEM_keypair(kem, public_key, private_key) == OQS_SUCCESS;
}

[[nodiscard]]
inline bool ml_kem_encaps( // NOLINT(readability-function-size)
    const MlKemVariant variant,
    const CryptoByte* public_key, std::size_t public_key_size,
    CryptoByte* ciphertext,    std::size_t ciphertext_size,
    CryptoByte* shared_secret, std::size_t shared_secret_size) noexcept
{
    const OQS_KEM* kem = detail::kem_for(variant);
    if (kem == nullptr) { return false; }
    if (public_key_size    != kem->length_public_key  ||
        ciphertext_size    < kem->length_ciphertext   ||
        shared_secret_size < kem->length_shared_secret) {
        return false;
    }
    return OQS_KEM_encaps(kem, ciphertext, shared_secret, public_key) == OQS_SUCCESS;
}

[[nodiscard]]
inline bool ml_kem_decaps( // NOLINT(readability-function-size)
    const MlKemVariant variant,
    const CryptoByte* private_key,  std::size_t private_key_size,
    const CryptoByte* ciphertext,   std::size_t ciphertext_size,
    CryptoByte*       shared_secret, std::size_t shared_secret_size) noexcept
{
    const OQS_KEM* kem = detail::kem_for(variant);
    if (kem == nullptr) { return false; }
    if (private_key_size   != kem->length_secret_key    ||
        ciphertext_size    != kem->length_ciphertext    ||
        shared_secret_size < kem->length_shared_secret) {
        return false;
    }
    return OQS_KEM_decaps(kem, shared_secret, ciphertext, private_key) == OQS_SUCCESS;
}

// --- ML-DSA ---

[[nodiscard]]
inline bool ml_dsa_keygen(
    const MlDsaVariant variant,
    CryptoByte* public_key,  std::size_t public_key_size,
    CryptoByte* private_key, std::size_t private_key_size) noexcept
{
    const OQS_SIG* sig = detail::sig_for(variant);
    if (sig == nullptr) { return false; }
    if (public_key_size  < sig->length_public_key ||
        private_key_size < sig->length_secret_key) {
        return false;
    }
    return OQS_SIG_keypair(sig, public_key, private_key) == OQS_SUCCESS;
}

[[nodiscard]]
inline bool ml_dsa_sign( // NOLINT(readability-function-size)
    const MlDsaVariant variant,
    const CryptoByte* private_key,  std::size_t private_key_size,
    const CryptoByte* message,      std::size_t message_size,
    CryptoByte*       signature,    std::size_t signature_size,
    std::size_t*      signature_len) noexcept
{
    const OQS_SIG* sig = detail::sig_for(variant);
    if (sig == nullptr) { return false; }
    if (private_key_size != sig->length_secret_key ||
        signature_size   < sig->length_signature) {
        return false;
    }
    return OQS_SIG_sign(sig, signature, signature_len,
                        message, message_size,
                        private_key) == OQS_SUCCESS;
}

[[nodiscard]]
inline bool ml_dsa_verify( // NOLINT(readability-function-size)
    const MlDsaVariant variant,
    const CryptoByte* public_key,  std::size_t public_key_size,
    const CryptoByte* message,     std::size_t message_size,
    const CryptoByte* signature,   std::size_t signature_len) noexcept
{
    const OQS_SIG* sig = detail::sig_for(variant);
    if (sig == nullptr) { return false; }
    if (public_key_size != sig->length_public_key ||
        signature_len   != sig->length_signature) {
        return false;
    }
    return OQS_SIG_verify(sig, message, message_size,
                          signature, signature_len,
                          public_key) == OQS_SUCCESS;
}

}  // namespace liboqs_pqc
