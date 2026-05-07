// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstddef>
#include <cstring>

// IA ASM primitives: SHA, HMAC, HKDF, AEAD.
#include "aes256_gcm.hpp"
#include "chacha20_poly1305.hpp"
#include "defs.hpp"
#include "hkdf.hpp"
#include "hmac.hpp"
#include "key_store.hpp"
#include "sha256.hpp"
#include "sha3.hpp"
#include "sha512.hpp"

// ARM ASM primitives: EC, RSA, PQC, random — all pure C++, x86-portable.
// ECDSA uses ia_asm/ecdsa.hpp (same math, ia_asm HMAC for RFC 6979).
#include "ecdsa.hpp"
#include "../arm_asm/ec_key_store.hpp"
#include "../arm_asm/p256_point.hpp"
#include "../arm_asm/p384_point.hpp"
#include "../arm_asm/p521_point.hpp"
#include "../arm_asm/pqc_key_store.hpp"
#include "../arm_asm/random.hpp"
#include "rsa.hpp"

// safe-crypto-lib shared headers (resolved via CMake include path).
#include "ml_dsa_variant.hpp"
#include "ml_kem_variant.hpp"
#include "secure_buffer.hpp"
#include "sha_variant.hpp"
#include "slh_dsa_variant.hpp"

#ifdef SAFE_CRYPTO_PQC_LIBOQS
#include "../arm_asm/liboqs_pqc.hpp"
#endif


// Intel x86_64 assembly/intrinsic backend.
// Hash/HMAC/HKDF/AEAD use IA ASM detail (SHA-NI, AES-NI, PCLMULQDQ, SSE2).
// EC/RSA/PQC/random use arm_asm::detail (pure C++ bignum — x86-portable).
//
// Target: x86_64 with AES-NI, SHA-NI, PCLMULQDQ, SSE2/SSSE3.
// Cross-compiled on Apple Silicon via -DCMAKE_OSX_ARCHITECTURES=x86_64;
// runs under Rosetta 2.
struct IaAsmBackend {
    using Status       = int;
    using KeyId        = unsigned int;
    using Algorithm    = unsigned int;
    using KdfOperation = ia_asm::detail::HkdfState;
    using KdfStep      = unsigned int;

    struct KeyAttributes {
        std::size_t key_bytes{0};
        arm_asm::detail::EcCurveId  ec_curve{arm_asm::detail::EcCurveId::None};
        arm_asm::detail::EcKeyKind  ec_kind{arm_asm::detail::EcKeyKind::None};
        arm_asm::detail::RsaKeyKind rsa_key_kind{arm_asm::detail::RsaKeyKind::None};
        std::size_t rsa_bits{0};
        arm_asm::detail::PqcKeyType pqc_type{arm_asm::detail::PqcKeyType::None};
        std::uint8_t pqc_variant{0};
    };

    static constexpr Status ok              = 0;
    static constexpr Status err_invalid_sig = 1;
    static constexpr Status err_invalid_arg = 2;

    [[nodiscard]]
    static KeyId null_key_id() noexcept { return 0U; }
    [[nodiscard]]
    static KeyAttributes make_key_attrs() noexcept { return {}; }
    [[nodiscard]]
    static KdfOperation  make_kdf_op()    noexcept { return {}; }

    [[nodiscard]]
    static Status crypto_init() { return ok; }

    [[nodiscard]]
    static Status generate_random(CryptoByte* buf, std::size_t len) {
        arm_asm::detail::generate_random_bytes(buf, len);
        return ok;
    }

    [[nodiscard]]
    static Status hash_compute(Algorithm alg, const CryptoByte* input, std::size_t input_len,
                               CryptoByte* output, std::size_t output_size, std::size_t* output_len)
    {
        if (alg == alg_sha(ShaVariant::Sha256)) {
            if (output_size < sha256_size_bytes) { return err_invalid_arg; }
            ia_asm::detail::sha256(input, input_len, output);
            *output_len = sha256_size_bytes;
            return ok;
        }
        if (alg == alg_sha(ShaVariant::Sha512)) {
            if (output_size < sha512_size_bytes) { return err_invalid_arg; }
            ia_asm::detail::sha512(input, input_len, output);
            *output_len = sha512_size_bytes;
            return ok;
        }
        if (alg == alg_sha(ShaVariant::Sha384)) {
            if (output_size < sha384_size_bytes) { return err_invalid_arg; }
            ia_asm::detail::sha384(input, input_len, output);
            *output_len = sha384_size_bytes;
            return ok;
        }
        if (alg == alg_sha(ShaVariant::Sha3_256)) {
            if (output_size < sha3_256_size_bytes) { return err_invalid_arg; }
            ia_asm::detail::sha3_256(input, input_len, output);
            *output_len = sha3_256_size_bytes;
            return ok;
        }
        if (alg == alg_sha(ShaVariant::Sha3_384)) {
            if (output_size < sha3_384_size_bytes) { return err_invalid_arg; }
            ia_asm::detail::sha3_384(input, input_len, output);
            *output_len = sha3_384_size_bytes;
            return ok;
        }
        if (alg == alg_sha(ShaVariant::Sha3_512)) {
            if (output_size < sha3_512_size_bytes) { return err_invalid_arg; }
            ia_asm::detail::sha3_512(input, input_len, output);
            *output_len = sha3_512_size_bytes;
            return ok;
        }
        return err_invalid_arg;
    }

    [[nodiscard]]
    static Status import_key(const KeyAttributes* attrs, const CryptoByte* key,
                             std::size_t key_len, KeyId* id) {
        if (attrs != nullptr && attrs->ec_curve != arm_asm::detail::EcCurveId::None) {
            const KeyId slot = arm_asm::detail::ec_key_store_import(
                attrs->ec_curve, attrs->ec_kind, key, key_len);
            if (slot == 0U) { return err_invalid_arg; }
            *id = slot;
            return ok;
        }
        if (attrs != nullptr && attrs->rsa_key_kind != arm_asm::detail::RsaKeyKind::None) {
            const KeyId slot = arm_asm::detail::rsa_key_store_import(
                attrs->rsa_key_kind, attrs->rsa_bits, key, key_len);
            if (slot == 0U) { return err_invalid_arg; }
            *id = slot;
            return ok;
        }
        if (attrs != nullptr && attrs->pqc_type != arm_asm::detail::PqcKeyType::None) {
            using arm_asm::detail::PqcKeyType;
            const bool is_private = (attrs->pqc_type == PqcKeyType::MlKemPrivate ||
                                     attrs->pqc_type == PqcKeyType::MlDsaPrivate);
            const CryptoByte* priv = is_private ? key : nullptr;
            const std::size_t priv_sz = is_private ? key_len : 0U;
            const CryptoByte* pub = is_private ? nullptr : key;
            const std::size_t pub_sz = is_private ? 0U : key_len;
            const KeyId slot = arm_asm::detail::pqc_key_store_import(
                attrs->pqc_type, attrs->pqc_variant, priv, priv_sz, pub, pub_sz);
            if (slot == 0U) { return err_invalid_arg; }
            *id = slot;
            return ok;
        }
        const KeyId slot = ia_asm::detail::key_store_import(key, key_len);
        if (slot == 0U) { return err_invalid_arg; }
        *id = slot;
        return ok;
    }

    [[nodiscard]]
    static Status generate_key(const KeyAttributes* attrs, KeyId* id) { // NOLINT(readability-function-size)
        if (attrs == nullptr) { return err_invalid_arg; }
        if (attrs->ec_curve != arm_asm::detail::EcCurveId::None) {
            using namespace arm_asm::detail;
            if (attrs->ec_curve == EcCurveId::P256) {
                constexpr std::size_t sk_len = 32; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
                FixedSecureBuffer<sk_len> sk{};
                for (int attempts = 0; attempts < 100; ++attempts) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
                    generate_random_bytes(sk.data(), sk_len);
                    const Fe256 s = p256_scalar_from_bytes32(sk.data());
                    if (!p256_scalar_is_zero(s)) {
                        fe256_to_bytes(s, sk.data());
                        const KeyId slot = ec_key_store_import(EcCurveId::P256, EcKeyKind::Private, sk.data(), sk_len);
                        if (slot == 0U) { return err_invalid_arg; }
                        *id = slot;
                        return ok;
                    }
                }
                return err_invalid_arg;
            }
            if (attrs->ec_curve == EcCurveId::P384) {
                constexpr std::size_t sk_len = 48; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
                FixedSecureBuffer<sk_len> sk{};
                for (int attempts = 0; attempts < 100; ++attempts) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
                    generate_random_bytes(sk.data(), sk_len);
                    const Fe384 s = p384_scalar_from_bytes48(sk.data());
                    if (!p384_scalar_is_zero(s)) {
                        fe384_to_bytes(s, sk.data());
                        const KeyId slot = ec_key_store_import(EcCurveId::P384, EcKeyKind::Private, sk.data(), sk_len);
                        if (slot == 0U) { return err_invalid_arg; }
                        *id = slot;
                        return ok;
                    }
                }
                return err_invalid_arg;
            }
            if (attrs->ec_curve == EcCurveId::P521) {
                constexpr std::size_t sk_len = 66; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
                FixedSecureBuffer<sk_len> sk{};
                for (int attempts = 0; attempts < 100; ++attempts) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
                    generate_random_bytes(sk.data(), sk_len);
                    const Fe521 s = p521_scalar_from_bytes66(sk.data());
                    if (!p521_scalar_is_zero(s)) {
                        fe521_to_bytes(s, sk.data());
                        const KeyId slot = ec_key_store_import(EcCurveId::P521, EcKeyKind::Private, sk.data(), sk_len);
                        if (slot == 0U) { return err_invalid_arg; }
                        *id = slot;
                        return ok;
                    }
                }
                return err_invalid_arg;
            }
            return err_invalid_arg;
        }
        if (attrs->rsa_key_kind == arm_asm::detail::RsaKeyKind::Private && attrs->rsa_bits > 0) {
            FixedSecureBuffer<arm_asm::detail::rsa_max_public_key_bytes> pub_tmp{};
            std::size_t pub_len = 0;
            const KeyId slot = arm_asm::detail::rsa_generate_key_pair(
                attrs->rsa_bits, pub_tmp.data(), arm_asm::detail::rsa_max_public_key_bytes, &pub_len);
            if (slot == 0U) { return err_invalid_arg; }
            *id = slot;
            return ok;
        }
        if (attrs->pqc_type != arm_asm::detail::PqcKeyType::None) {
#ifdef SAFE_CRYPTO_PQC_LIBOQS
            using arm_asm::detail::PqcKeyType;
            if (attrs->pqc_type == PqcKeyType::MlKemPrivate) {
                const auto v = static_cast<MlKemVariant>(attrs->pqc_variant);
                const std::size_t pub_sz  = ml_kem_public_key_size(v);
                const std::size_t priv_sz = ml_kem_private_key_size(v);
                auto* pub_buf  = new (std::nothrow) CryptoByte[pub_sz];   // NOLINT(cppcoreguidelines-owning-memory)
                auto* priv_buf = new (std::nothrow) CryptoByte[priv_sz];  // NOLINT(cppcoreguidelines-owning-memory)
                if (pub_buf == nullptr || priv_buf == nullptr) {
                    delete[] pub_buf;   // NOLINT(cppcoreguidelines-owning-memory)
                    delete[] priv_buf;  // NOLINT(cppcoreguidelines-owning-memory)
                    return err_invalid_arg;
                }
                const bool ok_kg = liboqs_pqc::ml_kem_keygen(v, pub_buf, pub_sz, priv_buf, priv_sz);
                if (!ok_kg) {
                    arm_asm::detail::secure_zero(pub_buf,  pub_sz);
                    arm_asm::detail::secure_zero(priv_buf, priv_sz);
                    delete[] pub_buf;   // NOLINT(cppcoreguidelines-owning-memory)
                    delete[] priv_buf;  // NOLINT(cppcoreguidelines-owning-memory)
                    return err_invalid_arg;
                }
                const KeyId slot = arm_asm::detail::pqc_key_store_import(
                    PqcKeyType::MlKemPrivate, attrs->pqc_variant,
                    priv_buf, priv_sz, pub_buf, pub_sz);
                arm_asm::detail::secure_zero(priv_buf, priv_sz);
                arm_asm::detail::secure_zero(pub_buf,  pub_sz);
                delete[] priv_buf;  // NOLINT(cppcoreguidelines-owning-memory)
                delete[] pub_buf;   // NOLINT(cppcoreguidelines-owning-memory)
                if (slot == 0U) { return err_invalid_arg; }
                *id = slot;
                return ok;
            }
            if (attrs->pqc_type == PqcKeyType::MlDsaPrivate) {
                const auto v = static_cast<MlDsaVariant>(attrs->pqc_variant);
                const std::size_t pub_sz  = ml_dsa_public_key_size(v);
                const std::size_t priv_sz = ml_dsa_private_key_size(v);
                auto* pub_buf  = new (std::nothrow) CryptoByte[pub_sz];   // NOLINT(cppcoreguidelines-owning-memory)
                auto* priv_buf = new (std::nothrow) CryptoByte[priv_sz];  // NOLINT(cppcoreguidelines-owning-memory)
                if (pub_buf == nullptr || priv_buf == nullptr) {
                    delete[] pub_buf;   // NOLINT(cppcoreguidelines-owning-memory)
                    delete[] priv_buf;  // NOLINT(cppcoreguidelines-owning-memory)
                    return err_invalid_arg;
                }
                const bool ok_kg = liboqs_pqc::ml_dsa_keygen(v, pub_buf, pub_sz, priv_buf, priv_sz);
                if (!ok_kg) {
                    arm_asm::detail::secure_zero(pub_buf,  pub_sz);
                    arm_asm::detail::secure_zero(priv_buf, priv_sz);
                    delete[] pub_buf;   // NOLINT(cppcoreguidelines-owning-memory)
                    delete[] priv_buf;  // NOLINT(cppcoreguidelines-owning-memory)
                    return err_invalid_arg;
                }
                const KeyId slot = arm_asm::detail::pqc_key_store_import(
                    PqcKeyType::MlDsaPrivate, attrs->pqc_variant,
                    priv_buf, priv_sz, pub_buf, pub_sz);
                arm_asm::detail::secure_zero(priv_buf, priv_sz);
                arm_asm::detail::secure_zero(pub_buf,  pub_sz);
                delete[] priv_buf;  // NOLINT(cppcoreguidelines-owning-memory)
                delete[] pub_buf;   // NOLINT(cppcoreguidelines-owning-memory)
                if (slot == 0U) { return err_invalid_arg; }
                *id = slot;
                return ok;
            }
#endif
            return err_invalid_arg;
        }
        if (attrs->key_bytes == 0) { return err_invalid_arg; }
        if (attrs->key_bytes > ia_asm::detail::key_store_max_bytes) { return err_invalid_arg; }
        FixedSecureBuffer<ia_asm::detail::key_store_max_bytes> buf;
        arm_asm::detail::generate_random_bytes(buf.data(), attrs->key_bytes);
        const KeyId slot = ia_asm::detail::key_store_import(buf.data(), attrs->key_bytes);
        if (slot == 0U) { return err_invalid_arg; }
        *id = slot;
        return ok;
    }

    [[nodiscard]]
    static Status destroy_key(KeyId id) {
        if (arm_asm::detail::ec_key_id_is_ec(id)) {
            arm_asm::detail::ec_key_store_destroy(id);
        } else if (arm_asm::detail::rsa_key_id_is_rsa(id)) {
            arm_asm::detail::rsa_key_store_destroy(id);
        } else if (arm_asm::detail::pqc_key_id_is_pqc(id)) {
            arm_asm::detail::pqc_key_store_destroy(id);
        } else {
            ia_asm::detail::key_store_destroy(id);
        }
        return ok;
    }

    [[nodiscard]]
    static Status export_key(KeyId id, CryptoByte* out, std::size_t size, std::size_t* len) {
        if (arm_asm::detail::rsa_key_id_is_rsa(id)) {
            using namespace arm_asm::detail;
            RsaKeyKind kind = RsaKeyKind::None;
            std::size_t bits = 0;
            const CryptoByte* key = nullptr;
            std::size_t key_len = 0;
            if (!rsa_key_store_get(id, &kind, &bits, &key, &key_len)) { return err_invalid_arg; }
            if (kind != RsaKeyKind::Private) { return err_invalid_arg; }
            if (size < key_len) { return err_invalid_arg; }
            std::memcpy(out, key, key_len);
            *len = key_len;
            return ok;
        }
        if (arm_asm::detail::ec_key_id_is_ec(id)) {
            using namespace arm_asm::detail;
            EcCurveId curve = EcCurveId::None;
            EcKeyKind kind  = EcKeyKind::None;
            const CryptoByte* key = nullptr;
            std::size_t key_len = 0;
            if (!ec_key_store_get(id, &curve, &kind, &key, &key_len)) { return err_invalid_arg; }
            if (kind != EcKeyKind::Private) { return err_invalid_arg; }
            if (size < key_len) { return err_invalid_arg; }
            std::memcpy(out, key, key_len);
            *len = key_len;
            return ok;
        }
        if (arm_asm::detail::pqc_key_id_is_pqc(id)) {
            const auto kv = arm_asm::detail::pqc_key_store_get_private(id);
            if (!kv) { return err_invalid_arg; }
            if (size < kv->data.size()) { return err_invalid_arg; }
            std::memcpy(out, kv->data.data(), kv->data.size());
            *len = kv->data.size();
            return ok;
        }
        const CryptoByte* key = nullptr;
        std::size_t key_len = 0;
        if (!ia_asm::detail::key_store_get(id, &key, &key_len)) { return err_invalid_arg; }
        if (size < key_len) { return err_invalid_arg; }
        std::memcpy(out, key, key_len);
        *len = key_len;
        return ok;
    }

    [[nodiscard]]
    static Status export_public_key(KeyId id, CryptoByte* out, std::size_t size,
                                    std::size_t* len) {
        using namespace arm_asm::detail;
        if (rsa_key_id_is_rsa(id)) {
            RsaKeyKind kind = RsaKeyKind::None;
            std::size_t bits = 0;
            const CryptoByte* key = nullptr;
            std::size_t key_len = 0;
            if (!rsa_key_store_get(id, &kind, &bits, &key, &key_len)) { return err_invalid_arg; }
            if (kind != RsaKeyKind::Private) { return err_invalid_arg; }
            return rsa_derive_public_key_der(key, key_len, out, size, len)
                ? ok : err_invalid_arg;
        }
        if (pqc_key_id_is_pqc(id)) {
            const auto kv = pqc_key_store_get_public(id);
            if (!kv) { return err_invalid_arg; }
            if (size < kv->data.size()) { return err_invalid_arg; }
            std::memcpy(out, kv->data.data(), kv->data.size());
            *len = kv->data.size();
            return ok;
        }
        if (!ec_key_id_is_ec(id)) { return err_invalid_arg; }
        EcCurveId curve = EcCurveId::None;
        EcKeyKind kind  = EcKeyKind::None;
        const CryptoByte* key = nullptr;
        std::size_t key_len = 0;
        if (!ec_key_store_get(id, &curve, &kind, &key, &key_len)) { return err_invalid_arg; }
        if (kind == EcKeyKind::Public) {
            if (size < key_len) { return err_invalid_arg; }
            std::memcpy(out, key, key_len);
            *len = key_len;
            return ok;
        }
        if (kind != EcKeyKind::Private) { return err_invalid_arg; }
        if (curve == EcCurveId::P256) {
            constexpr std::size_t pk_len = 65; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
            if (size < pk_len) { return err_invalid_arg; }
            p256_compute_public_key(key, out);
            *len = pk_len;
            return ok;
        }
        if (curve == EcCurveId::P384) {
            constexpr std::size_t pk_len = 97; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
            if (size < pk_len) { return err_invalid_arg; }
            p384_compute_public_key(key, out);
            *len = pk_len;
            return ok;
        }
        if (curve == EcCurveId::P521) {
            constexpr std::size_t pk_len = 133; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
            if (size < pk_len) { return err_invalid_arg; }
            p521_compute_public_key(key, out);
            *len = pk_len;
            return ok;
        }
        return err_invalid_arg;
    }

    [[nodiscard]]
    static Status mac_compute(  // NOLINT(readability-function-size)
                              KeyId id, Algorithm alg, // NOLINT(bugprone-easily-swappable-parameters)
                              const CryptoByte* msg, std::size_t msg_len,
                              CryptoByte* out, std::size_t out_size, std::size_t* out_len) {
        const CryptoByte* key = nullptr;
        std::size_t key_len = 0;
        if (!ia_asm::detail::key_store_get(id, &key, &key_len)) { return err_invalid_arg; }
        if (alg == alg_hmac(ShaVariant::Sha256)) {
            if (out_size < sha256_size_bytes) { return err_invalid_arg; }
            ia_asm::detail::hmac_sha256(key, key_len, msg, msg_len, out);
            *out_len = sha256_size_bytes;
            return ok;
        }
        if (alg == alg_hmac(ShaVariant::Sha512)) {
            if (out_size < sha512_size_bytes) { return err_invalid_arg; }
            ia_asm::detail::hmac_sha512(key, key_len, msg, msg_len, out);
            *out_len = sha512_size_bytes;
            return ok;
        }
        if (alg == alg_hmac(ShaVariant::Sha384)) {
            if (out_size < sha384_size_bytes) { return err_invalid_arg; }
            ia_asm::detail::hmac_sha384(key, key_len, msg, msg_len, out);
            *out_len = sha384_size_bytes;
            return ok;
        }
        if (alg == alg_hmac(ShaVariant::Sha3_256)) {
            if (out_size < sha3_256_size_bytes) { return err_invalid_arg; }
            ia_asm::detail::hmac_sha3_256(key, key_len, msg, msg_len, out);
            *out_len = sha3_256_size_bytes;
            return ok;
        }
        if (alg == alg_hmac(ShaVariant::Sha3_384)) {
            if (out_size < sha3_384_size_bytes) { return err_invalid_arg; }
            ia_asm::detail::hmac_sha3_384(key, key_len, msg, msg_len, out);
            *out_len = sha3_384_size_bytes;
            return ok;
        }
        if (alg == alg_hmac(ShaVariant::Sha3_512)) {
            if (out_size < sha3_512_size_bytes) { return err_invalid_arg; }
            ia_asm::detail::hmac_sha3_512(key, key_len, msg, msg_len, out);
            *out_len = sha3_512_size_bytes;
            return ok;
        }
        return err_invalid_arg;
    }

    [[nodiscard]]
    static Status mac_verify(KeyId id, Algorithm alg,
                             const CryptoByte* msg, std::size_t msg_len,
                             const CryptoByte* mac, std::size_t mac_len) {
        FixedSecureBuffer<sha512_size_bytes> expected;
        std::size_t expected_len = 0;
        const Status s = mac_compute(id, alg, msg, msg_len,
                                     expected.data(), expected.size(), &expected_len);
        if (s != ok) { return s; }
        if (mac_len != expected_len) { return err_invalid_sig; }
        unsigned int diff = 0;
        for (std::size_t i = 0; i < expected_len; ++i) {
            diff |= static_cast<unsigned int>(mac[i]) ^ static_cast<unsigned int>(expected[i]); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        }
        return diff == 0U ? ok : err_invalid_sig;
    }

    [[nodiscard]]
    static Status aead_encrypt(  // NOLINT(readability-function-size)
                               KeyId id, Algorithm alg, // NOLINT(bugprone-easily-swappable-parameters)
                               const CryptoByte* nonce, std::size_t nonce_len,
                               const CryptoByte* aad, std::size_t aad_len,
                               const CryptoByte* pt, std::size_t pt_len,
                               CryptoByte* out, std::size_t out_size, std::size_t* out_len) {
        const CryptoByte* key = nullptr;
        std::size_t key_len = 0;
        if (!ia_asm::detail::key_store_get(id, &key, &key_len)) { return err_invalid_arg; }
        if (key_len != 32) { return err_invalid_arg; }  // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        if (alg == alg_aes_gcm()) {
            if (nonce_len != ia_asm::detail::aes_gcm_iv_bytes) { return err_invalid_arg; }
            if (pt_len > SIZE_MAX - ia_asm::detail::aes_gcm_tag_bytes) { return err_invalid_arg; }
            if (out_size < pt_len + ia_asm::detail::aes_gcm_tag_bytes) { return err_invalid_arg; }
            ia_asm::detail::aes256_gcm_encrypt(key, nonce, aad, aad_len, pt, pt_len, out);
            *out_len = pt_len + ia_asm::detail::aes_gcm_tag_bytes;
            return ok;
        }
        if (alg == alg_chacha20_poly1305()) {
            if (nonce_len != ia_asm::detail::chacha20_poly1305_nonce_bytes) { return err_invalid_arg; }
            if (pt_len > SIZE_MAX - ia_asm::detail::chacha20_poly1305_tag_bytes) { return err_invalid_arg; }
            if (out_size < pt_len + ia_asm::detail::chacha20_poly1305_tag_bytes) { return err_invalid_arg; }
            ia_asm::detail::chacha20_poly1305_encrypt(key, nonce, aad, aad_len, pt, pt_len, out);
            *out_len = pt_len + ia_asm::detail::chacha20_poly1305_tag_bytes;
            return ok;
        }
        return err_invalid_arg;
    }

    [[nodiscard]]
    static Status aead_decrypt(  // NOLINT(readability-function-size)
                               KeyId id, Algorithm alg, // NOLINT(bugprone-easily-swappable-parameters)
                               const CryptoByte* nonce, std::size_t nonce_len,
                               const CryptoByte* aad, std::size_t aad_len,
                               const CryptoByte* ct, std::size_t ct_len,
                               CryptoByte* out, std::size_t out_size, std::size_t* out_len) {
        const CryptoByte* key = nullptr;
        std::size_t key_len = 0;
        if (!ia_asm::detail::key_store_get(id, &key, &key_len)) { return err_invalid_arg; }
        if (key_len != 32) { return err_invalid_arg; }  // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        if (alg == alg_aes_gcm()) {
            if (nonce_len != ia_asm::detail::aes_gcm_iv_bytes) { return err_invalid_arg; }
            if (ct_len < ia_asm::detail::aes_gcm_tag_bytes) { return err_invalid_arg; }
            const std::size_t pt_len = ct_len - ia_asm::detail::aes_gcm_tag_bytes;
            if (out_size < pt_len) { return err_invalid_arg; }
            if (!ia_asm::detail::aes256_gcm_decrypt(key, nonce, aad, aad_len, ct, ct_len, out)) {
                return err_invalid_sig;
            }
            *out_len = pt_len;
            return ok;
        }
        if (alg == alg_chacha20_poly1305()) {
            if (nonce_len != ia_asm::detail::chacha20_poly1305_nonce_bytes) { return err_invalid_arg; }
            if (ct_len < ia_asm::detail::chacha20_poly1305_tag_bytes) { return err_invalid_arg; }
            const std::size_t pt_len = ct_len - ia_asm::detail::chacha20_poly1305_tag_bytes;
            if (out_size < pt_len) { return err_invalid_arg; }
            if (!ia_asm::detail::chacha20_poly1305_decrypt(key, nonce, aad, aad_len, ct, ct_len, out)) {
                return err_invalid_sig;
            }
            *out_len = pt_len;
            return ok;
        }
        return err_invalid_arg;
    }

    [[nodiscard]]
    static Status sign_message(  // NOLINT(readability-function-size)
                               KeyId id, Algorithm alg,
                               const CryptoByte* msg, std::size_t msg_len,
                               CryptoByte* sig, std::size_t sig_size, std::size_t* sig_len) {
        using namespace arm_asm::detail;
        if (alg == alg_rsa_pss()) {
            if (!rsa_key_id_is_rsa(id)) { return err_invalid_arg; }
            RsaKeyKind kind = RsaKeyKind::None;
            std::size_t bits = 0;
            const CryptoByte* key = nullptr;
            std::size_t key_len = 0;
            if (!rsa_key_store_get(id, &kind, &bits, &key, &key_len)) { return err_invalid_arg; }
            if (kind != RsaKeyKind::Private) { return err_invalid_arg; }
            if (!rsa_pss_sign(bits, key, key_len, msg, msg_len, sig, sig_size, sig_len)) {
                return err_invalid_arg;
            }
            return ok;
        }
#ifdef SAFE_CRYPTO_PQC_LIBOQS
        if (alg == alg_ml_dsa(MlDsaVariant::Dsa44) ||
            alg == alg_ml_dsa(MlDsaVariant::Dsa65) ||
            alg == alg_ml_dsa(MlDsaVariant::Dsa87)) {
            if (!pqc_key_id_is_pqc(id)) { return err_invalid_arg; }
            const auto kv = pqc_key_store_get_private(id);
            if (!kv || kv->type != PqcKeyType::MlDsaPrivate) { return err_invalid_arg; }
            const auto v = static_cast<MlDsaVariant>(kv->variant);
            if (sig_size < ml_dsa_signature_size(v)) { return err_invalid_arg; }
            if (!liboqs_pqc::ml_dsa_sign(v, kv->data.data(), kv->data.size(), msg, msg_len, sig, sig_size, sig_len)) {
                return err_invalid_arg;
            }
            return ok;
        }
#endif
        if (alg != alg_ecdsa()) { return err_invalid_arg; }
        if (!ec_key_id_is_ec(id)) { return err_invalid_arg; }
        EcCurveId curve = EcCurveId::None;
        EcKeyKind kind  = EcKeyKind::None;
        const CryptoByte* key = nullptr;
        std::size_t key_len = 0;
        if (!ec_key_store_get(id, &curve, &kind, &key, &key_len)) { return err_invalid_arg; }
        if (kind != EcKeyKind::Private) { return err_invalid_arg; }
        if (curve == EcCurveId::P256) {
            constexpr std::size_t hash_len = 32; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
            constexpr std::size_t sig_len_expected = 64; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
            if (sig_size < sig_len_expected) { return err_invalid_arg; }
            if (key_len != hash_len) { return err_invalid_arg; }
            uint8_t hash[hash_len] = {}; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
            ia_asm::detail::sha256(msg, msg_len, hash);
            if (!ia_asm::detail::p256_ecdsa_sign(key, hash, sig)) { return err_invalid_arg; }
            *sig_len = sig_len_expected;
            return ok;
        }
        if (curve == EcCurveId::P384) {
            constexpr std::size_t hash_len = 48; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
            constexpr std::size_t sig_len_expected = 96; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
            if (sig_size < sig_len_expected) { return err_invalid_arg; }
            if (key_len != hash_len) { return err_invalid_arg; }
            uint8_t hash[hash_len] = {}; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
            ia_asm::detail::sha384(msg, msg_len, hash);
            if (!ia_asm::detail::p384_ecdsa_sign(key, hash, sig)) { return err_invalid_arg; }
            *sig_len = sig_len_expected;
            return ok;
        }
        if (curve == EcCurveId::P521) {
            constexpr std::size_t hash_len = 64; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
            constexpr std::size_t sk_len = 66; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
            constexpr std::size_t sig_len_expected = 132; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
            if (sig_size < sig_len_expected) { return err_invalid_arg; }
            if (key_len != sk_len) { return err_invalid_arg; }
            uint8_t hash[hash_len] = {}; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
            ia_asm::detail::sha512(msg, msg_len, hash);
            if (!ia_asm::detail::p521_ecdsa_sign(key, hash, sig)) { return err_invalid_arg; }
            *sig_len = sig_len_expected;
            return ok;
        }
        return err_invalid_arg;
    }

    [[nodiscard]]
    static Status verify_message(KeyId id, Algorithm alg,
                                 const CryptoByte* msg, std::size_t msg_len,
                                 const CryptoByte* sig, std::size_t sig_len) {
        using namespace arm_asm::detail;
        if (alg == alg_rsa_pss()) {
            if (!rsa_key_id_is_rsa(id)) { return err_invalid_arg; }
            RsaKeyKind kind = RsaKeyKind::None;
            std::size_t bits = 0;
            const CryptoByte* key = nullptr;
            std::size_t key_len = 0;
            if (!rsa_key_store_get(id, &kind, &bits, &key, &key_len)) { return err_invalid_arg; }
            if (kind != RsaKeyKind::Public) { return err_invalid_arg; }
            return rsa_pss_verify(bits, key, key_len, msg, msg_len, sig, sig_len)
                ? ok : err_invalid_sig;
        }
#ifdef SAFE_CRYPTO_PQC_LIBOQS
        if (alg == alg_ml_dsa(MlDsaVariant::Dsa44) ||
            alg == alg_ml_dsa(MlDsaVariant::Dsa65) ||
            alg == alg_ml_dsa(MlDsaVariant::Dsa87)) {
            if (!pqc_key_id_is_pqc(id)) { return err_invalid_arg; }
            const auto kv = pqc_key_store_get_public(id);
            if (!kv || (kv->type != PqcKeyType::MlDsaPublic && kv->type != PqcKeyType::MlDsaPrivate)) { return err_invalid_arg; }
            const auto v = static_cast<MlDsaVariant>(kv->variant);
            return liboqs_pqc::ml_dsa_verify(v, kv->data.data(), kv->data.size(), msg, msg_len, sig, sig_len)
                ? ok : err_invalid_sig;
        }
#endif
        if (alg != alg_ecdsa()) { return err_invalid_arg; }
        if (!ec_key_id_is_ec(id)) { return err_invalid_arg; }
        EcCurveId curve = EcCurveId::None;
        EcKeyKind kind  = EcKeyKind::None;
        const CryptoByte* key = nullptr;
        std::size_t key_len = 0;
        if (!ec_key_store_get(id, &curve, &kind, &key, &key_len)) { return err_invalid_arg; }
        if (kind != EcKeyKind::Public) { return err_invalid_arg; }
        if (curve == EcCurveId::P256) {
            constexpr std::size_t hash_len = 32; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
            constexpr std::size_t expected_sig_len = 64; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
            constexpr std::size_t pk_len = 65; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
            if (sig_len != expected_sig_len || key_len != pk_len) { return err_invalid_arg; }
            uint8_t hash[hash_len] = {}; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
            ia_asm::detail::sha256(msg, msg_len, hash);
            return ia_asm::detail::p256_ecdsa_verify(key, hash, sig) ? ok : err_invalid_sig;
        }
        if (curve == EcCurveId::P384) {
            constexpr std::size_t hash_len = 48; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
            constexpr std::size_t expected_sig_len = 96; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
            constexpr std::size_t pk_len = 97; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
            if (sig_len != expected_sig_len || key_len != pk_len) { return err_invalid_arg; }
            uint8_t hash[hash_len] = {}; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
            ia_asm::detail::sha384(msg, msg_len, hash);
            return ia_asm::detail::p384_ecdsa_verify(key, hash, sig) ? ok : err_invalid_sig;
        }
        if (curve == EcCurveId::P521) {
            constexpr std::size_t hash_len = 64; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
            constexpr std::size_t expected_sig_len = 132; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
            constexpr std::size_t pk_len = 133; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
            if (sig_len != expected_sig_len || key_len != pk_len) { return err_invalid_arg; }
            uint8_t hash[hash_len] = {}; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
            ia_asm::detail::sha512(msg, msg_len, hash);
            return ia_asm::detail::p521_ecdsa_verify(key, hash, sig) ? ok : err_invalid_sig;
        }
        return err_invalid_arg;
    }

    [[nodiscard]]
    static Status raw_key_agreement(  // NOLINT(readability-function-size)
                                    Algorithm alg, KeyId id,
                                    const CryptoByte* peer, std::size_t peer_len,
                                    CryptoByte* out, std::size_t out_size, std::size_t* out_len) {
        using namespace arm_asm::detail;
        if (alg != alg_ecdh()) { return err_invalid_arg; }
        if (!ec_key_id_is_ec(id)) { return err_invalid_arg; }
        EcCurveId curve = EcCurveId::None;
        EcKeyKind kind  = EcKeyKind::None;
        const CryptoByte* key = nullptr;
        std::size_t key_len = 0;
        if (!ec_key_store_get(id, &curve, &kind, &key, &key_len)) { return err_invalid_arg; }
        if (kind != EcKeyKind::Private) { return err_invalid_arg; }
        if (curve == EcCurveId::P256) {
            constexpr std::size_t pk_len = 65; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
            constexpr std::size_t ss_len = 32; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
            if (peer_len != pk_len || peer[0] != 0x04U) { return err_invalid_arg; }
            if (out_size < ss_len) { return err_invalid_arg; }
            if (key_len != ss_len) { return err_invalid_arg; }
            const Fe256 Qx = fe256_from_bytes(peer + 1);  // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
            const Fe256 Qy = fe256_from_bytes(peer + 33); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic,cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
            if (!p256_validate_public_point(Qx, Qy)) { return err_invalid_arg; }
            const P256Point Q{.X = Qx, .Y = Qy, .Z = fe256_one};
            const P256Point S = p256_to_affine(p256_scalar_mul(Q, key));
            if (p256_point_is_identity(S)) { return err_invalid_arg; }
            fe256_to_bytes(S.X, out);
            *out_len = ss_len;
            return ok;
        }
        if (curve == EcCurveId::P384) {
            constexpr std::size_t pk_len = 97; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
            constexpr std::size_t ss_len = 48; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
            if (peer_len != pk_len || peer[0] != 0x04U) { return err_invalid_arg; }
            if (out_size < ss_len) { return err_invalid_arg; }
            if (key_len != ss_len) { return err_invalid_arg; }
            const Fe384 Qx = fe384_from_bytes(peer + 1);  // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
            const Fe384 Qy = fe384_from_bytes(peer + 49); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic,cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
            if (!p384_validate_public_point(Qx, Qy)) { return err_invalid_arg; }
            const P384Point Q{.X = Qx, .Y = Qy, .Z = fe384_one};
            const P384Point S = p384_to_affine(p384_scalar_mul(Q, key));
            if (p384_point_is_identity(S)) { return err_invalid_arg; }
            fe384_to_bytes(S.X, out);
            *out_len = ss_len;
            return ok;
        }
        if (curve == EcCurveId::P521) {
            constexpr std::size_t pk_len = 133; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
            constexpr std::size_t ss_len = 66; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
            if (peer_len != pk_len || peer[0] != 0x04U) { return err_invalid_arg; }
            if (out_size < ss_len) { return err_invalid_arg; }
            if (key_len != ss_len) { return err_invalid_arg; }
            if ((peer[1]  & 0xFEU) != 0U) { return err_invalid_arg; } // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
            if ((peer[67] & 0xFEU) != 0U) { return err_invalid_arg; } // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic,cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
            const Fe521 Qx = fe521_from_bytes(peer + 1);   // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
            const Fe521 Qy = fe521_from_bytes(peer + 67);  // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic,cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
            if (!p521_validate_public_point(Qx, Qy)) { return err_invalid_arg; }
            const P521Point Q{.X = Qx, .Y = Qy, .Z = fe521_one};
            const P521Point S = p521_to_affine(p521_scalar_mul(Q, key));
            if (p521_point_is_identity(S)) { return err_invalid_arg; }
            fe521_to_bytes(S.X, out);
            *out_len = ss_len;
            return ok;
        }
        return err_invalid_arg;
    }

    [[nodiscard]]
    static Status asymmetric_encrypt(  // NOLINT(readability-function-size)
                                     KeyId id, Algorithm alg,
                                     const CryptoByte* pt, std::size_t pt_len,
                                     const CryptoByte* salt, std::size_t salt_len,
                                     CryptoByte* out, std::size_t out_size, std::size_t* out_len) {
        using namespace arm_asm::detail;
        if (alg != alg_rsa_oaep()) { return err_invalid_arg; }
        if (!rsa_key_id_is_rsa(id)) { return err_invalid_arg; }
        RsaKeyKind kind = RsaKeyKind::None;
        std::size_t bits = 0;
        const CryptoByte* key = nullptr;
        std::size_t key_len = 0;
        if (!rsa_key_store_get(id, &kind, &bits, &key, &key_len)) { return err_invalid_arg; }
        if (kind != RsaKeyKind::Public) { return err_invalid_arg; }
        if (!rsa_oaep_encrypt(bits, key, key_len, pt, pt_len, salt, salt_len, out, out_size, out_len)) {
            return err_invalid_arg;
        }
        return ok;
    }

    [[nodiscard]]
    static Status asymmetric_decrypt(  // NOLINT(readability-function-size)
                                     KeyId id, Algorithm alg,
                                     const CryptoByte* ct, std::size_t ct_len,
                                     const CryptoByte* salt, std::size_t salt_len,
                                     CryptoByte* out, std::size_t out_size, std::size_t* out_len) {
        using namespace arm_asm::detail;
        if (alg != alg_rsa_oaep()) { return err_invalid_arg; }
        if (!rsa_key_id_is_rsa(id)) { return err_invalid_arg; }
        RsaKeyKind kind = RsaKeyKind::None;
        std::size_t bits = 0;
        const CryptoByte* key = nullptr;
        std::size_t key_len = 0;
        if (!rsa_key_store_get(id, &kind, &bits, &key, &key_len)) { return err_invalid_arg; }
        if (kind != RsaKeyKind::Private) { return err_invalid_arg; }
        if (!rsa_oaep_decrypt(bits, key, key_len, ct, ct_len, salt, salt_len, out, out_size, out_len)) {
            return err_invalid_arg;
        }
        return ok;
    }

    [[nodiscard]]
    static Status key_derivation_setup(KdfOperation* op, Algorithm alg) {
        ia_asm::detail::HkdfAlg ha = ia_asm::detail::HkdfAlg::None;
        if (alg == alg_hkdf())              { ha = ia_asm::detail::HkdfAlg::Hkdf; }
        else if (alg == alg_hkdf_expand())  { ha = ia_asm::detail::HkdfAlg::HkdfExpand; }
        else { return err_invalid_arg; }
        return ia_asm::detail::hkdf_setup(op, ha) == 0 ? ok : err_invalid_arg;
    }

    [[nodiscard]]
    static Status key_derivation_input_key(KdfOperation* op, KdfStep /*step*/, KeyId id) {
        return ia_asm::detail::hkdf_input_key(op, id) == 0 ? ok : err_invalid_arg;
    }

    [[nodiscard]]
    static Status key_derivation_input_bytes(KdfOperation* op, KdfStep step,
                                             const CryptoByte* data, std::size_t len) {
        return ia_asm::detail::hkdf_input_bytes(op, step, data, len) == 0 ? ok : err_invalid_arg;
    }

    [[nodiscard]]
    static Status key_derivation_output_bytes(KdfOperation* op, CryptoByte* out, std::size_t len) {
        return ia_asm::detail::hkdf_output_bytes(op, out, len) == 0 ? ok : err_invalid_arg;
    }

    [[nodiscard]]
    static Status key_derivation_abort(KdfOperation* op) {
        if (op != nullptr) { op->zeroize(); }
        return ok;
    }

    static constexpr Algorithm alg_base_hash = 0x0100U;
    static constexpr Algorithm alg_base_hmac = 0x0200U;

    [[nodiscard]]
    static Algorithm alg_sha(ShaVariant v)  noexcept { return alg_base_hash | static_cast<Algorithm>(v); }
    [[nodiscard]]
    static Algorithm alg_hmac(ShaVariant v) noexcept { return alg_base_hmac | static_cast<Algorithm>(v); }
    [[nodiscard]]
    static constexpr Algorithm alg_ecdsa()             noexcept { return 0x0501U; }
    [[nodiscard]]
    static constexpr Algorithm alg_ecdh()              noexcept { return 0x0502U; }
    [[nodiscard]]
    static constexpr Algorithm alg_hkdf()              noexcept { return 0x0301U; }
    [[nodiscard]]
    static constexpr Algorithm alg_hkdf_expand()       noexcept { return 0x0302U; }
    [[nodiscard]]
    static constexpr Algorithm alg_aes_gcm()           noexcept { return 0x0401U; }
    [[nodiscard]]
    static constexpr Algorithm alg_chacha20_poly1305() noexcept { return 0x0402U; }
    [[nodiscard]]
    static constexpr Algorithm alg_rsa_oaep()          noexcept { return 0x0601U; }
    [[nodiscard]]
    static constexpr Algorithm alg_rsa_pss()           noexcept { return 0x0602U; }

    [[nodiscard]]
    static constexpr KdfStep kdf_step_secret() noexcept { return 2U; }
    [[nodiscard]]
    static constexpr KdfStep kdf_step_salt()   noexcept { return 0U; }
    [[nodiscard]]
    static constexpr KdfStep kdf_step_info()   noexcept { return 1U; }

    // NOLINT(readability-named-parameter)
    [[nodiscard]]
    static KeyAttributes make_hkdf_derive_attrs(std::size_t bits)              noexcept { return {.key_bytes = bits / 8U}; }
    [[nodiscard]]
    static KeyAttributes make_hkdf_expand_derive_attrs(std::size_t bits)       noexcept { return {.key_bytes = bits / 8U}; }
    [[nodiscard]]
    static KeyAttributes make_hmac_generate_attrs(ShaVariant /*v*/, std::size_t bits) noexcept { return {.key_bytes = bits / 8U}; }
    [[nodiscard]]
    static KeyAttributes make_hmac_verify_attrs(ShaVariant /*v*/, std::size_t bits)   noexcept { return {.key_bytes = bits / 8U}; }
    [[nodiscard]]
    static KeyAttributes make_ecdsa_generate_attrs(std::size_t bits) noexcept {
        const auto curve = ec_curve_id_for_bits(bits);
        return {.key_bytes = ec_private_key_export_size(bits), .ec_curve = curve, .ec_kind = arm_asm::detail::EcKeyKind::Private};
    }
    [[nodiscard]]
    static KeyAttributes make_ecdsa_sign_attrs(std::size_t bits) noexcept {
        const auto curve = ec_curve_id_for_bits(bits);
        return {.key_bytes = ec_private_key_export_size(bits), .ec_curve = curve, .ec_kind = arm_asm::detail::EcKeyKind::Private};
    }
    [[nodiscard]]
    static KeyAttributes make_ecdsa_verify_attrs(std::size_t bits) noexcept {
        const auto curve = ec_curve_id_for_bits(bits);
        return {.key_bytes = ec_public_key_export_size(bits), .ec_curve = curve, .ec_kind = arm_asm::detail::EcKeyKind::Public};
    }
    [[nodiscard]]
    static KeyAttributes make_ecdh_generate_attrs(std::size_t bits) noexcept {
        const auto curve = ec_curve_id_for_bits(bits);
        return {.key_bytes = ec_private_key_export_size(bits), .ec_curve = curve, .ec_kind = arm_asm::detail::EcKeyKind::Private};
    }
    [[nodiscard]]
    static KeyAttributes make_ecdh_agree_attrs(std::size_t bits) noexcept {
        const auto curve = ec_curve_id_for_bits(bits);
        return {.key_bytes = ec_private_key_export_size(bits), .ec_curve = curve, .ec_kind = arm_asm::detail::EcKeyKind::Private};
    }
    [[nodiscard]]
    static KeyAttributes make_aes256_gcm_encrypt_attrs()          noexcept { return {.key_bytes = aes256_key_size_bytes}; }
    [[nodiscard]]
    static KeyAttributes make_aes256_gcm_decrypt_attrs()          noexcept { return {.key_bytes = aes256_key_size_bytes}; }
    [[nodiscard]]
    static KeyAttributes make_chacha20_poly1305_encrypt_attrs()   noexcept { return {.key_bytes = chacha20_key_size_bytes}; }
    [[nodiscard]]
    static KeyAttributes make_chacha20_poly1305_decrypt_attrs()   noexcept { return {.key_bytes = chacha20_key_size_bytes}; }
    [[nodiscard]]
    static KeyAttributes make_rsa_oaep_encrypt_attrs(std::size_t bits) noexcept {
        return {.rsa_key_kind = arm_asm::detail::RsaKeyKind::Public, .rsa_bits = bits};
    }
    [[nodiscard]]
    static KeyAttributes make_rsa_oaep_decrypt_attrs(std::size_t bits) noexcept {
        return {.rsa_key_kind = arm_asm::detail::RsaKeyKind::Private, .rsa_bits = bits};
    }
    [[nodiscard]]
    static KeyAttributes make_rsa_pss_sign_attrs(std::size_t bits) noexcept {
        return {.rsa_key_kind = arm_asm::detail::RsaKeyKind::Private, .rsa_bits = bits};
    }
    [[nodiscard]]
    static KeyAttributes make_rsa_pss_verify_attrs(std::size_t bits) noexcept {
        return {.rsa_key_kind = arm_asm::detail::RsaKeyKind::Public, .rsa_bits = bits};
    }
    [[nodiscard]]
    static KeyAttributes make_rsa_key_pair_attrs(std::size_t bits) noexcept {
        return {.rsa_key_kind = arm_asm::detail::RsaKeyKind::Private, .rsa_bits = bits};
    }

    [[nodiscard]]
    static constexpr auto ec_curve_id_for_bits(std::size_t bits) noexcept -> arm_asm::detail::EcCurveId {
        if (bits == 256U) { return arm_asm::detail::EcCurveId::P256; } // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        if (bits == 384U) { return arm_asm::detail::EcCurveId::P384; } // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        return arm_asm::detail::EcCurveId::P521;
    }
    [[nodiscard]]
    static std::size_t ecdsa_sign_output_size(std::size_t bits)          noexcept { return ((bits + 7U) / 8U) * 2U; }
    [[nodiscard]]
    static std::size_t ecdh_shared_secret_size(std::size_t bits)         noexcept { return (bits + 7U) / 8U; }
    [[nodiscard]]
    static std::size_t ec_private_key_export_size(std::size_t bits)      noexcept { return (bits + 7U) / 8U; }
    [[nodiscard]]
    static std::size_t ec_public_key_export_size(std::size_t bits)       noexcept { return (((bits + 7U) / 8U) * 2U) + 1U; }
    [[nodiscard]]
    static std::size_t aes_gcm_encrypt_output_size(std::size_t pt_len)   noexcept { return pt_len <= SIZE_MAX - ia_asm::detail::aes_gcm_tag_bytes ? pt_len + ia_asm::detail::aes_gcm_tag_bytes : 0; }
    [[nodiscard]]
    static std::size_t aes_gcm_decrypt_output_size(std::size_t ct_len)   noexcept { return ct_len > ia_asm::detail::aes_gcm_tag_bytes ? ct_len - ia_asm::detail::aes_gcm_tag_bytes : 0; }
    [[nodiscard]]
    static std::size_t chacha20_encrypt_output_size(std::size_t pt_len)  noexcept { return pt_len <= SIZE_MAX - ia_asm::detail::chacha20_poly1305_tag_bytes ? pt_len + ia_asm::detail::chacha20_poly1305_tag_bytes : 0; }
    [[nodiscard]]
    static std::size_t chacha20_decrypt_output_size(std::size_t ct_len)  noexcept { return ct_len > ia_asm::detail::chacha20_poly1305_tag_bytes ? ct_len - ia_asm::detail::chacha20_poly1305_tag_bytes : 0; }
    [[nodiscard]]
    static std::size_t rsa_oaep_encrypt_output_size(std::size_t bits)    noexcept { return bits / 8U; }
    [[nodiscard]]
    static std::size_t rsa_oaep_decrypt_output_size(std::size_t bits)    noexcept { return bits / 8U; }
    [[nodiscard]]
    static std::size_t rsa_pss_sign_output_size(std::size_t bits)        noexcept { return bits / 8U; }
    [[nodiscard]]
    static std::size_t rsa_private_key_export_size(std::size_t bits)     noexcept { return (9U * (bits / 16U + 6U)) + 14U; }
    [[nodiscard]]
    static std::size_t rsa_public_key_export_size(std::size_t bits)      noexcept { return (bits / 8U) + 50U; }

    // SLH-DSA — not yet implemented; all operations return err_invalid_arg.
    [[nodiscard]]
    static Algorithm alg_slh_dsa(const SlhDsaVariant) noexcept { return 0x0701U; }
    [[nodiscard]]
    static KeyAttributes make_slh_dsa_sign_attrs(const SlhDsaVariant)     noexcept { return {}; }
    [[nodiscard]]
    static KeyAttributes make_slh_dsa_verify_attrs(const SlhDsaVariant)   noexcept { return {}; }
    [[nodiscard]]
    static KeyAttributes make_slh_dsa_generate_attrs(const SlhDsaVariant) noexcept { return {}; }
    [[nodiscard]]
    static std::size_t slh_dsa_sign_output_size(const SlhDsaVariant v)          noexcept { return slh_dsa_signature_size(v); }
    [[nodiscard]]
    static std::size_t slh_dsa_private_key_export_size(const SlhDsaVariant v)   noexcept { return slh_dsa_private_key_size(v); }
    [[nodiscard]]
    static std::size_t slh_dsa_public_key_export_size(const SlhDsaVariant v)    noexcept { return slh_dsa_public_key_size(v); }

    [[nodiscard]]
    static Algorithm alg_ml_dsa(const MlDsaVariant) noexcept { return 0x0702U; }
    [[nodiscard]]
    static KeyAttributes make_ml_dsa_sign_attrs(const MlDsaVariant v) noexcept {
#ifdef SAFE_CRYPTO_PQC_LIBOQS
        return {.pqc_type = arm_asm::detail::PqcKeyType::MlDsaPrivate,
                .pqc_variant = static_cast<std::uint8_t>(v)};
#else
        (void)v; return {};
#endif
    }
    [[nodiscard]]
    static KeyAttributes make_ml_dsa_verify_attrs(const MlDsaVariant v) noexcept {
#ifdef SAFE_CRYPTO_PQC_LIBOQS
        return {.pqc_type = arm_asm::detail::PqcKeyType::MlDsaPublic,
                .pqc_variant = static_cast<std::uint8_t>(v)};
#else
        (void)v; return {};
#endif
    }
    [[nodiscard]]
    static KeyAttributes make_ml_dsa_generate_attrs(const MlDsaVariant v) noexcept {
#ifdef SAFE_CRYPTO_PQC_LIBOQS
        return {.pqc_type = arm_asm::detail::PqcKeyType::MlDsaPrivate,
                .pqc_variant = static_cast<std::uint8_t>(v)};
#else
        (void)v; return {};
#endif
    }
    [[nodiscard]]
    static std::size_t ml_dsa_sign_output_size(const MlDsaVariant v)          noexcept { return ml_dsa_signature_size(v); }
    [[nodiscard]]
    static std::size_t ml_dsa_private_key_export_size(const MlDsaVariant v)   noexcept { return ml_dsa_private_key_size(v); }
    [[nodiscard]]
    static std::size_t ml_dsa_public_key_export_size(const MlDsaVariant v)    noexcept { return ml_dsa_public_key_size(v); }

    [[nodiscard]]
    static Algorithm alg_ml_kem(const MlKemVariant) noexcept { return 0x0703U; }
    [[nodiscard]]
    static KeyAttributes make_ml_kem_generate_attrs(const MlKemVariant v) noexcept {
#ifdef SAFE_CRYPTO_PQC_LIBOQS
        return {.pqc_type = arm_asm::detail::PqcKeyType::MlKemPrivate,
                .pqc_variant = static_cast<std::uint8_t>(v)};
#else
        (void)v; return {};
#endif
    }
    [[nodiscard]]
    static KeyAttributes make_ml_kem_encap_attrs(const MlKemVariant v) noexcept {
#ifdef SAFE_CRYPTO_PQC_LIBOQS
        return {.pqc_type = arm_asm::detail::PqcKeyType::MlKemPublic,
                .pqc_variant = static_cast<std::uint8_t>(v)};
#else
        (void)v; return {};
#endif
    }
    [[nodiscard]]
    static KeyAttributes make_ml_kem_decap_attrs(const MlKemVariant v) noexcept {
#ifdef SAFE_CRYPTO_PQC_LIBOQS
        return {.pqc_type = arm_asm::detail::PqcKeyType::MlKemPrivate,
                .pqc_variant = static_cast<std::uint8_t>(v)};
#else
        (void)v; return {};
#endif
    }
    [[nodiscard]]
    static std::size_t ml_kem_ciphertext_size(const MlKemVariant v)          noexcept { return ::ml_kem_ciphertext_size(v); }
    [[nodiscard]]
    static std::size_t ml_kem_shared_secret_size(const MlKemVariant v)       noexcept { return ::ml_kem_shared_secret_size(v); }
    [[nodiscard]]
    static std::size_t ml_kem_private_key_export_size(const MlKemVariant v)  noexcept { return ml_kem_private_key_size(v); }
    [[nodiscard]]
    static std::size_t ml_kem_public_key_export_size(const MlKemVariant v)   noexcept { return ml_kem_public_key_size(v); }

    [[nodiscard]]
    static Status kem_encapsulate(
        const KeyId id, const Algorithm alg,
        CryptoByte* ciphertext,    std::size_t ciphertext_size,    std::size_t* ciphertext_len,
        CryptoByte* shared_secret, std::size_t shared_secret_size, std::size_t* shared_secret_len) noexcept {
#ifdef SAFE_CRYPTO_PQC_LIBOQS
        using arm_asm::detail::PqcKeyType;
        if (alg != alg_ml_kem(MlKemVariant::Kem512) &&
            alg != alg_ml_kem(MlKemVariant::Kem768) &&
            alg != alg_ml_kem(MlKemVariant::Kem1024)) { return err_invalid_arg; }
        if (!arm_asm::detail::pqc_key_id_is_pqc(id)) { return err_invalid_arg; }
        const auto kv_enc = arm_asm::detail::pqc_key_store_get_public(id);
        if (!kv_enc || (kv_enc->type != PqcKeyType::MlKemPublic && kv_enc->type != PqcKeyType::MlKemPrivate)) { return err_invalid_arg; }
        const auto v = static_cast<MlKemVariant>(kv_enc->variant);
        if (ciphertext_size    < ml_kem_ciphertext_size(v))    { return err_invalid_arg; }
        if (shared_secret_size < ml_kem_shared_secret_size(v)) { return err_invalid_arg; }
        if (!liboqs_pqc::ml_kem_encaps(v, kv_enc->data.data(), kv_enc->data.size(),
                                        ciphertext,    ciphertext_size,
                                        shared_secret, shared_secret_size)) { return err_invalid_arg; }
        *ciphertext_len    = ml_kem_ciphertext_size(v);
        *shared_secret_len = ml_kem_shared_secret_size(v);
        return ok;
#else
        (void)id; (void)alg;
        (void)ciphertext; (void)ciphertext_size; (void)ciphertext_len;
        (void)shared_secret; (void)shared_secret_size; (void)shared_secret_len;
        return err_invalid_arg;
#endif
    }

    [[nodiscard]]
    static Status kem_decapsulate(
        const KeyId id, const Algorithm alg,
        const CryptoByte* ciphertext, std::size_t ciphertext_len,
        CryptoByte* shared_secret, std::size_t shared_secret_size, std::size_t* shared_secret_len) noexcept {
#ifdef SAFE_CRYPTO_PQC_LIBOQS
        using arm_asm::detail::PqcKeyType;
        if (alg != alg_ml_kem(MlKemVariant::Kem512) &&
            alg != alg_ml_kem(MlKemVariant::Kem768) &&
            alg != alg_ml_kem(MlKemVariant::Kem1024)) { return err_invalid_arg; }
        if (!arm_asm::detail::pqc_key_id_is_pqc(id)) { return err_invalid_arg; }
        const auto kv_dec = arm_asm::detail::pqc_key_store_get_private(id);
        if (!kv_dec || kv_dec->type != PqcKeyType::MlKemPrivate) { return err_invalid_arg; }
        const auto v = static_cast<MlKemVariant>(kv_dec->variant);
        if (shared_secret_size < ml_kem_shared_secret_size(v)) { return err_invalid_arg; }
        if (!liboqs_pqc::ml_kem_decaps(v, kv_dec->data.data(), kv_dec->data.size(),
                                        ciphertext, ciphertext_len,
                                        shared_secret, shared_secret_size)) { return err_invalid_arg; }
        *shared_secret_len = ml_kem_shared_secret_size(v);
        return ok;
#else
        (void)id; (void)alg;
        (void)ciphertext; (void)ciphertext_len;
        (void)shared_secret; (void)shared_secret_size; (void)shared_secret_len;
        return err_invalid_arg;
#endif
    }
};
