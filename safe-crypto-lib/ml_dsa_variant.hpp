/*
Copyright Permanence AI, 2026. All rights reserved.

*/

#pragma once

#include <cstddef>
#include <cstdint>


enum class MlDsaVariant : std::uint8_t {
    Dsa44,
    Dsa65,
    Dsa87,
};

// FIPS 204, Table 1 — private key sizes (skEncode bit-packed output).
constexpr std::size_t ml_dsa_private_key_size(const MlDsaVariant v) {
    switch (v) {
        case MlDsaVariant::Dsa44: return 2560U;
        case MlDsaVariant::Dsa65: return 4032U;
        case MlDsaVariant::Dsa87: return 4896U;
    }
}

// FIPS 204, Table 1 — public key sizes (pkEncode bit-packed output).
constexpr std::size_t ml_dsa_public_key_size(const MlDsaVariant v) {
    switch (v) {
        case MlDsaVariant::Dsa44: return 1312U;
        case MlDsaVariant::Dsa65: return 1952U;
        case MlDsaVariant::Dsa87: return 2592U;
    }
}

// FIPS 204, Table 1 — signature sizes (sigEncode bit-packed output).
constexpr std::size_t ml_dsa_signature_size(const MlDsaVariant v) {
    switch (v) {
        case MlDsaVariant::Dsa44: return 2420U;
        case MlDsaVariant::Dsa65: return 3309U;
        case MlDsaVariant::Dsa87: return 4627U;
    }
}
