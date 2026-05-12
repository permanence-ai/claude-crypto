// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstddef>
#include <cstdint>


enum class MlKemVariant : std::uint8_t {
    Kem512,
    Kem768,
    Kem1024,
};

// FIPS 203, Table 2 — encapsulation key (public key) sizes in bytes.
constexpr std::size_t ml_kem_512_public_key_bytes  =  800U;
constexpr std::size_t ml_kem_768_public_key_bytes  = 1184U;
constexpr std::size_t ml_kem_1024_public_key_bytes = 1568U;

// FIPS 203, Table 2 — decapsulation key (private key) sizes in bytes.
constexpr std::size_t ml_kem_512_private_key_bytes  = 1632U;
constexpr std::size_t ml_kem_768_private_key_bytes  = 2400U;
constexpr std::size_t ml_kem_1024_private_key_bytes = 3168U;

// FIPS 203, Table 2 — ciphertext sizes in bytes.
constexpr std::size_t ml_kem_512_ciphertext_bytes  =  768U;
constexpr std::size_t ml_kem_768_ciphertext_bytes  = 1088U;
constexpr std::size_t ml_kem_1024_ciphertext_bytes = 1568U;

// FIPS 203, Section 2 — shared secret size (same for all parameter sets).
constexpr std::size_t ml_kem_shared_secret_bytes = 32U;

// FIPS 203, Table 2 — encapsulation key (public key) sizes.
constexpr std::size_t ml_kem_public_key_size(const MlKemVariant v) {
    switch (v) {
        case MlKemVariant::Kem512:  return ml_kem_512_public_key_bytes;
        case MlKemVariant::Kem768:  return ml_kem_768_public_key_bytes;
        case MlKemVariant::Kem1024: return ml_kem_1024_public_key_bytes;
    }
}

// FIPS 203, Table 2 — decapsulation key (private key) sizes.
constexpr std::size_t ml_kem_private_key_size(const MlKemVariant v) {
    switch (v) {
        case MlKemVariant::Kem512:  return ml_kem_512_private_key_bytes;
        case MlKemVariant::Kem768:  return ml_kem_768_private_key_bytes;
        case MlKemVariant::Kem1024: return ml_kem_1024_private_key_bytes;
    }
}

// FIPS 203, Table 2 — ciphertext sizes.
constexpr std::size_t ml_kem_ciphertext_size(const MlKemVariant v) {
    switch (v) {
        case MlKemVariant::Kem512:  return ml_kem_512_ciphertext_bytes;
        case MlKemVariant::Kem768:  return ml_kem_768_ciphertext_bytes;
        case MlKemVariant::Kem1024: return ml_kem_1024_ciphertext_bytes;
    }
}

// FIPS 203, Section 2 — shared secret is always 32 bytes for all parameter sets.
constexpr std::size_t ml_kem_shared_secret_size(const MlKemVariant /*variant*/) {
    return ml_kem_shared_secret_bytes;
}
