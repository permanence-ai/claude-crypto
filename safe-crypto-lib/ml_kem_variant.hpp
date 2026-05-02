/*
Copyright Permanence AI, 2026. All rights reserved.

*/

#pragma once

#include <cstddef>
#include <cstdint>


enum class MlKemVariant : std::uint8_t {
    Kem512,
    Kem768,
    Kem1024,
};

// FIPS 203, Table 2 — encapsulation key (public key) sizes.
constexpr std::size_t ml_kem_public_key_size(const MlKemVariant v) {
    switch (v) {
        case MlKemVariant::Kem512:  return  800U;
        case MlKemVariant::Kem768:  return 1184U;
        case MlKemVariant::Kem1024: return 1568U;
    }
}

// FIPS 203, Table 2 — decapsulation key (private key) sizes.
constexpr std::size_t ml_kem_private_key_size(const MlKemVariant v) {
    switch (v) {
        case MlKemVariant::Kem512:  return 1632U;
        case MlKemVariant::Kem768:  return 2400U;
        case MlKemVariant::Kem1024: return 3168U;
    }
}

// FIPS 203, Table 2 — ciphertext sizes.
constexpr std::size_t ml_kem_ciphertext_size(const MlKemVariant v) {
    switch (v) {
        case MlKemVariant::Kem512:  return  768U;
        case MlKemVariant::Kem768:  return 1088U;
        case MlKemVariant::Kem1024: return 1568U;
    }
}

// FIPS 203, Section 2 — shared secret is always 32 bytes for all parameter sets.
constexpr std::size_t ml_kem_shared_secret_size(const MlKemVariant) {
    return 32U;
}
