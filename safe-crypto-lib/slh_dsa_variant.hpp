// SPDX-License-Identifier: Apache-2.0

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

// FIPS 205, Table 2 — named size constants.
// Private key = SK.seed || SK.prf || PK.seed || PK.root = 4n bytes (n = security parameter).
// Public key = PK.seed || PK.root = 2n bytes.
constexpr std::size_t slh_dsa_128_priv_key_bytes  =  64U;   // n=16, 4n=64
constexpr std::size_t slh_dsa_192_priv_key_bytes  =  96U;
constexpr std::size_t slh_dsa_256_priv_key_bytes  = 128U;
constexpr std::size_t slh_dsa_128_pub_key_bytes   =  32U;
constexpr std::size_t slh_dsa_192_pub_key_bytes   =  48U;
constexpr std::size_t slh_dsa_256_pub_key_bytes   =  64U;
constexpr std::size_t slh_dsa_128s_sig_bytes      =  7856U;
constexpr std::size_t slh_dsa_128f_sig_bytes      = 17088U;
constexpr std::size_t slh_dsa_192s_sig_bytes      = 16224U;
constexpr std::size_t slh_dsa_192f_sig_bytes      = 35664U;
constexpr std::size_t slh_dsa_256s_sig_bytes      = 29792U;
constexpr std::size_t slh_dsa_256f_sig_bytes      = 49856U;

// FIPS 205, Table 2 — private key sizes (seed || root || SK.prf = 2n || n).
constexpr std::size_t slh_dsa_private_key_size(const SlhDsaVariant v) {
    switch (v) {
        case SlhDsaVariant::Sha2_128s: [[fallthrough]];
        case SlhDsaVariant::Sha2_128f: return slh_dsa_128_priv_key_bytes;
        case SlhDsaVariant::Sha2_192s: [[fallthrough]];
        case SlhDsaVariant::Sha2_192f: return slh_dsa_192_priv_key_bytes;
        case SlhDsaVariant::Sha2_256s: [[fallthrough]];
        case SlhDsaVariant::Sha2_256f: return slh_dsa_256_priv_key_bytes;
    }
}

// FIPS 205, Table 2 — public key sizes (PK.seed || PK.root = 2n).
constexpr std::size_t slh_dsa_public_key_size(const SlhDsaVariant v) {
    switch (v) {
        case SlhDsaVariant::Sha2_128s: [[fallthrough]];
        case SlhDsaVariant::Sha2_128f: return slh_dsa_128_pub_key_bytes;
        case SlhDsaVariant::Sha2_192s: [[fallthrough]];
        case SlhDsaVariant::Sha2_192f: return slh_dsa_192_pub_key_bytes;
        case SlhDsaVariant::Sha2_256s: [[fallthrough]];
        case SlhDsaVariant::Sha2_256f: return slh_dsa_256_pub_key_bytes;
    }
}

// FIPS 205, Table 2 — signature sizes.
constexpr std::size_t slh_dsa_signature_size(const SlhDsaVariant v) {
    switch (v) {
        case SlhDsaVariant::Sha2_128s: return slh_dsa_128s_sig_bytes;
        case SlhDsaVariant::Sha2_128f: return slh_dsa_128f_sig_bytes;
        case SlhDsaVariant::Sha2_192s: return slh_dsa_192s_sig_bytes;
        case SlhDsaVariant::Sha2_192f: return slh_dsa_192f_sig_bytes;
        case SlhDsaVariant::Sha2_256s: return slh_dsa_256s_sig_bytes;
        case SlhDsaVariant::Sha2_256f: return slh_dsa_256f_sig_bytes;
    }
}
