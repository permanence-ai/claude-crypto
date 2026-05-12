// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstddef>
#include <cstdint>


enum class MlDsaVariant : std::uint8_t {
    Dsa44,
    Dsa65,
    Dsa87,
};

// FIPS 204, Table 1 — private key sizes in bytes (skEncode bit-packed output).
constexpr std::size_t ml_dsa_44_private_key_bytes = 2560U;
constexpr std::size_t ml_dsa_65_private_key_bytes = 4032U;
constexpr std::size_t ml_dsa_87_private_key_bytes = 4896U;

// FIPS 204, Table 1 — public key sizes in bytes (pkEncode bit-packed output).
constexpr std::size_t ml_dsa_44_public_key_bytes = 1312U;
constexpr std::size_t ml_dsa_65_public_key_bytes = 1952U;
constexpr std::size_t ml_dsa_87_public_key_bytes = 2592U;

// FIPS 204, Table 1 — signature sizes in bytes (sigEncode bit-packed output).
constexpr std::size_t ml_dsa_44_signature_bytes = 2420U;
constexpr std::size_t ml_dsa_65_signature_bytes = 3309U;
constexpr std::size_t ml_dsa_87_signature_bytes = 4627U;

// FIPS 204, Table 1 — private key sizes (skEncode bit-packed output).
constexpr std::size_t ml_dsa_private_key_size(const MlDsaVariant v) {
    switch (v) {
        case MlDsaVariant::Dsa44: return ml_dsa_44_private_key_bytes;
        case MlDsaVariant::Dsa65: return ml_dsa_65_private_key_bytes;
        case MlDsaVariant::Dsa87: return ml_dsa_87_private_key_bytes;
    }
}

// FIPS 204, Table 1 — public key sizes (pkEncode bit-packed output).
constexpr std::size_t ml_dsa_public_key_size(const MlDsaVariant v) {
    switch (v) {
        case MlDsaVariant::Dsa44: return ml_dsa_44_public_key_bytes;
        case MlDsaVariant::Dsa65: return ml_dsa_65_public_key_bytes;
        case MlDsaVariant::Dsa87: return ml_dsa_87_public_key_bytes;
    }
}

// FIPS 204, Table 1 — signature sizes (sigEncode bit-packed output).
constexpr std::size_t ml_dsa_signature_size(const MlDsaVariant v) {
    switch (v) {
        case MlDsaVariant::Dsa44: return ml_dsa_44_signature_bytes;
        case MlDsaVariant::Dsa65: return ml_dsa_65_signature_bytes;
        case MlDsaVariant::Dsa87: return ml_dsa_87_signature_bytes;
    }
}
