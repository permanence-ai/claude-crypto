/*
Copyright Permanence AI, 2026. All rights reserved.

*/

#pragma once

#include <cstddef>
#include <cstdint>


enum class SlhDsaVariant : std::uint8_t {
    // SHA2 hash family (FIPS 205)
    Sha2_128s,
    Sha2_128f,
    Sha2_192s,
    Sha2_192f,
    Sha2_256s,
    Sha2_256f,
};

// FIPS 205, Table 2 — private key sizes (seed || root || SK.prf = 2n || n).
constexpr std::size_t slh_dsa_private_key_size(const SlhDsaVariant v) {
    switch (v) {
        case SlhDsaVariant::Sha2_128s: [[fallthrough]];
        case SlhDsaVariant::Sha2_128f: return 64U;
        case SlhDsaVariant::Sha2_192s: [[fallthrough]];
        case SlhDsaVariant::Sha2_192f: return 96U;
        case SlhDsaVariant::Sha2_256s: [[fallthrough]];
        case SlhDsaVariant::Sha2_256f: return 128U;
    }
}

// FIPS 205, Table 2 — public key sizes (PK.seed || PK.root = 2n).
constexpr std::size_t slh_dsa_public_key_size(const SlhDsaVariant v) {
    switch (v) {
        case SlhDsaVariant::Sha2_128s: [[fallthrough]];
        case SlhDsaVariant::Sha2_128f: return 32U;
        case SlhDsaVariant::Sha2_192s: [[fallthrough]];
        case SlhDsaVariant::Sha2_192f: return 48U;
        case SlhDsaVariant::Sha2_256s: [[fallthrough]];
        case SlhDsaVariant::Sha2_256f: return 64U;
    }
}

// FIPS 205, Table 2 — signature sizes.
constexpr std::size_t slh_dsa_signature_size(const SlhDsaVariant v) {
    switch (v) {
        case SlhDsaVariant::Sha2_128s: return  7856U;
        case SlhDsaVariant::Sha2_128f: return 17088U;
        case SlhDsaVariant::Sha2_192s: return 16224U;
        case SlhDsaVariant::Sha2_192f: return 35664U;
        case SlhDsaVariant::Sha2_256s: return 29792U;
        case SlhDsaVariant::Sha2_256f: return 49856U;
    }
}
