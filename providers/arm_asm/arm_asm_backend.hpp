// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <array>
#include <cstddef>
#include <cstring>
#include <expected>
#include <span>

#include "aes256_gcm.hpp"
#include "chacha20_poly1305.hpp"
#include "defs.hpp"
#include "ec_key_store.hpp"
#include "ecdsa.hpp"
#include "hkdf.hpp"
#include "hmac.hpp"
#include "key_store.hpp"
#include "p256_point.hpp"
#include "p384_point.hpp"
#include "p521_point.hpp"
#include "random.hpp"
#include "rsa.hpp"
#include "secure_buffer.hpp"
#include "sha256.hpp"
#include "sha3.hpp"
#include "sha512.hpp"
#include "crypto_provider.hpp"
#include "ml_dsa_variant.hpp"
#include "ml_kem_variant.hpp"
#include "pqc_key_store.hpp"
#include "sha_variant.hpp"
#include "slh_dsa_variant.hpp"

#ifdef SAFE_CRYPTO_PQC_LIBOQS
#include "liboqs_pqc.hpp"
#endif


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

    // KeyAttributes carries either symmetric key size, EC curve/kind, RSA key info, or PQC key type.
    // key_bytes == 0 and all others == None means "not applicable".
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
    static Status crypto_init()                                               { return ok; }
    [[nodiscard]]
    static auto generate_random(const std::size_t len)
        -> std::expected<SecureBuffer, Status>
    {
        SecureBuffer output(len);
        arm_asm::detail::generate_random_bytes(output.data(), len);
        return output;
    }
    [[nodiscard]]
    static auto hash_compute(const Algorithm alg, const CByteVSpan input)
        -> std::expected<SecureBuffer, Status>
    {
        if (alg == alg_sha(ShaVariant::Sha256)) {
            SecureBuffer output(sha256_size_bytes);
            arm_asm::detail::sha256(input.data(), input.size(), ByteSpan<sha256_digest_bytes>{output.data(), sha256_digest_bytes});
            return output;
        }
        if (alg == alg_sha(ShaVariant::Sha512)) {
            SecureBuffer output(sha512_size_bytes);
            arm_asm::detail::sha512(input.data(), input.size(), ByteSpan<sha512_digest_bytes>{output.data(), sha512_digest_bytes});
            return output;
        }
        if (alg == alg_sha(ShaVariant::Sha384)) {
            SecureBuffer output(sha384_size_bytes);
            arm_asm::detail::sha384(input.data(), input.size(), ByteSpan<sha384_digest_bytes>{output.data(), sha384_digest_bytes});
            return output;
        }
        if (alg == alg_sha(ShaVariant::Sha3_256)) {
            SecureBuffer output(sha3_256_size_bytes);
            arm_asm::detail::sha3_256(input.data(), input.size(), ByteSpan<sha256_digest_bytes>{output.data(), sha256_digest_bytes});
            return output;
        }
        if (alg == alg_sha(ShaVariant::Sha3_384)) {
            SecureBuffer output(sha3_384_size_bytes);
            arm_asm::detail::sha3_384(input.data(), input.size(), ByteSpan<sha384_digest_bytes>{output.data(), sha384_digest_bytes});
            return output;
        }
        if (alg == alg_sha(ShaVariant::Sha3_512)) {
            SecureBuffer output(sha3_512_size_bytes);
            arm_asm::detail::sha3_512(input.data(), input.size(), ByteSpan<sha512_digest_bytes>{output.data(), sha512_digest_bytes});
            return output;
        }
        return std::unexpected(err_invalid_arg);
    }
    [[nodiscard]]
    static auto import_key(const KeyAttributes* attrs, const CByteVSpan key) // NOLINT(readability-function-size,readability-function-cognitive-complexity)
        -> std::expected<KeyId, Status> {
        if (attrs != nullptr && attrs->ec_curve != arm_asm::detail::EcCurveId::None) {
            const KeyId slot = arm_asm::detail::ec_key_store_import(
                attrs->ec_curve, attrs->ec_kind, key.data(), key.size());
            if (slot == 0U) { return std::unexpected(err_invalid_arg); }
            return slot;
        }
        if (attrs != nullptr && attrs->rsa_key_kind != arm_asm::detail::RsaKeyKind::None) {
            const KeyId slot = arm_asm::detail::rsa_key_store_import(
                attrs->rsa_key_kind, attrs->rsa_bits, key.data(), key.size());
            if (slot == 0U) { return std::unexpected(err_invalid_arg); }
            return slot;
        }
        if (attrs != nullptr && attrs->pqc_type != arm_asm::detail::PqcKeyType::None) {
            using arm_asm::detail::PqcKeyType;
            const bool is_private = (attrs->pqc_type == PqcKeyType::MlKemPrivate ||
                                     attrs->pqc_type == PqcKeyType::MlDsaPrivate);
            const CryptoByte* priv = is_private ? key.data() : nullptr;
            const std::size_t priv_sz = is_private ? key.size() : 0U;
            const CryptoByte* pub = is_private ? nullptr : key.data();
            const std::size_t pub_sz = is_private ? 0U : key.size();
            const KeyId slot = arm_asm::detail::pqc_key_store_import(
                attrs->pqc_type, attrs->pqc_variant, priv, priv_sz, pub, pub_sz);
            if (slot == 0U) { return std::unexpected(err_invalid_arg); }
            return slot;
        }
        const KeyId slot = arm_asm::detail::key_store_import(key.data(), key.size());
        if (slot == 0U) { return std::unexpected(err_invalid_arg); }
        return slot;
    }
    [[nodiscard]]
    static auto generate_key(const KeyAttributes* attrs) -> std::expected<KeyId, Status> { // NOLINT(readability-function-size,readability-function-cognitive-complexity)
        if (attrs == nullptr) { return std::unexpected(err_invalid_arg); }
        if (attrs->ec_curve != arm_asm::detail::EcCurveId::None) {
            // Generate EC private key: random scalar in [1, n-1].
            using namespace arm_asm::detail;
            if (attrs->ec_curve == EcCurveId::P256) {
                constexpr std::size_t sk_len = 32;
                FixedSecureBuffer<sk_len> sk{};
                // Rejection sample: generate random bytes, check in [1, n-1].
                for (int attempts = 0; attempts < 100; ++attempts) {
                    generate_random_bytes(sk.data(), sk_len);
                    const Fe256 s = p256_scalar_from_bytes32(CByteSpan<p256_scalar_bytes>{sk.data(), p256_scalar_bytes});
                    if (!p256_scalar_is_zero(s)) {
                        // p256_scalar_from_bytes32 already reduces mod n, so s < n.
                        fe256_to_bytes(s, ByteSpan<p256_scalar_bytes>{sk.data(), p256_scalar_bytes});
                        const KeyId slot = ec_key_store_import(EcCurveId::P256, EcKeyKind::Private, sk.data(), sk_len); // NOLINT(cppcoreguidelines-init-variables)
                        if (slot == 0U) { return std::unexpected(err_invalid_arg); }
                        return slot; // NOLINT(bugprone-narrowing-conversions,cppcoreguidelines-narrowing-conversions)
                    }
                }
                return std::unexpected(err_invalid_arg);
            }
            if (attrs->ec_curve == EcCurveId::P384) {
                constexpr std::size_t sk_len = 48;
                FixedSecureBuffer<sk_len> sk{};
                for (int attempts = 0; attempts < 100; ++attempts) {
                    generate_random_bytes(sk.data(), sk_len);
                    const Fe384 s = p384_scalar_from_bytes48(CByteSpan<p384_scalar_bytes>{sk.data(), p384_scalar_bytes});
                    if (!p384_scalar_is_zero(s)) {
                        fe384_to_bytes(s, ByteSpan<p384_scalar_bytes>{sk.data(), p384_scalar_bytes});
                        const KeyId slot = ec_key_store_import(EcCurveId::P384, EcKeyKind::Private, sk.data(), sk_len); // NOLINT(cppcoreguidelines-init-variables)
                        if (slot == 0U) { return std::unexpected(err_invalid_arg); }
                        return slot; // NOLINT(bugprone-narrowing-conversions,cppcoreguidelines-narrowing-conversions)
                    }
                }
                return std::unexpected(err_invalid_arg);
            }
            if (attrs->ec_curve == EcCurveId::P521) {
                constexpr std::size_t sk_len = 66;
                FixedSecureBuffer<sk_len> sk{};
                for (int attempts = 0; attempts < 100; ++attempts) {
                    generate_random_bytes(sk.data(), sk_len);
                    const Fe521 s = p521_scalar_from_bytes66(CByteSpan<p521_scalar_bytes>{sk.data(), p521_scalar_bytes});
                    if (!p521_scalar_is_zero(s)) {
                        fe521_to_bytes(s, ByteSpan<p521_scalar_bytes>{sk.data(), p521_scalar_bytes});
                        const KeyId slot = ec_key_store_import(EcCurveId::P521, EcKeyKind::Private, sk.data(), sk_len); // NOLINT(cppcoreguidelines-init-variables)
                        if (slot == 0U) { return std::unexpected(err_invalid_arg); }
                        return slot; // NOLINT(bugprone-narrowing-conversions,cppcoreguidelines-narrowing-conversions)
                    }
                }
                return std::unexpected(err_invalid_arg);
            }
            return std::unexpected(err_invalid_arg);
        }
        if (attrs->rsa_key_kind == arm_asm::detail::RsaKeyKind::Private && attrs->rsa_bits > 0) {
            // RSA key pair generation: use PSA, store private key, discard public from here.
            // The caller (generate_rsa_key_impl) will separately call export_public_key.
            FixedSecureBuffer<arm_asm::detail::rsa_max_public_key_bytes> pub_tmp{};
            std::size_t pub_len = 0;
            const KeyId slot = arm_asm::detail::rsa_generate_key_pair(
                attrs->rsa_bits, pub_tmp.data(), arm_asm::detail::rsa_max_public_key_bytes, &pub_len);
            if (slot == 0U) { return std::unexpected(err_invalid_arg); }
            return slot;
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
                    return std::unexpected(err_invalid_arg);
                }
                const bool ok_kg = liboqs_pqc::ml_kem_keygen(v, pub_buf, pub_sz, priv_buf, priv_sz);
                if (!ok_kg) {
                    detail::secure_zero(pub_buf,  pub_sz);
                    detail::secure_zero(priv_buf, priv_sz);
                    delete[] pub_buf;   // NOLINT(cppcoreguidelines-owning-memory)
                    delete[] priv_buf;  // NOLINT(cppcoreguidelines-owning-memory)
                    return std::unexpected(err_invalid_arg);
                }
                // Store [private | public] so export_public_key can retrieve the public portion.
                const KeyId slot = arm_asm::detail::pqc_key_store_import(
                    PqcKeyType::MlKemPrivate, attrs->pqc_variant,
                    priv_buf, priv_sz, pub_buf, pub_sz);
                detail::secure_zero(priv_buf, priv_sz);
                detail::secure_zero(pub_buf,  pub_sz);
                delete[] priv_buf;  // NOLINT(cppcoreguidelines-owning-memory)
                delete[] pub_buf;   // NOLINT(cppcoreguidelines-owning-memory)
                if (slot == 0U) { return std::unexpected(err_invalid_arg); }
                return slot;
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
                    return std::unexpected(err_invalid_arg);
                }
                const bool ok_kg = liboqs_pqc::ml_dsa_keygen(v, pub_buf, pub_sz, priv_buf, priv_sz);
                if (!ok_kg) {
                    detail::secure_zero(pub_buf,  pub_sz);
                    detail::secure_zero(priv_buf, priv_sz);
                    delete[] pub_buf;   // NOLINT(cppcoreguidelines-owning-memory)
                    delete[] priv_buf;  // NOLINT(cppcoreguidelines-owning-memory)
                    return std::unexpected(err_invalid_arg);
                }
                const KeyId slot = arm_asm::detail::pqc_key_store_import(
                    PqcKeyType::MlDsaPrivate, attrs->pqc_variant,
                    priv_buf, priv_sz, pub_buf, pub_sz);
                detail::secure_zero(priv_buf, priv_sz);
                detail::secure_zero(pub_buf,  pub_sz);
                delete[] priv_buf;  // NOLINT(cppcoreguidelines-owning-memory)
                delete[] pub_buf;   // NOLINT(cppcoreguidelines-owning-memory)
                if (slot == 0U) { return std::unexpected(err_invalid_arg); }
                return slot;
            }
#endif
            return std::unexpected(err_invalid_arg);
        }
        if (attrs->key_bytes == 0) { return std::unexpected(err_invalid_arg); }
        if (attrs->key_bytes > arm_asm::detail::key_store_max_bytes) { return std::unexpected(err_invalid_arg); }
        FixedSecureBuffer<arm_asm::detail::key_store_max_bytes> buf;
        arm_asm::detail::generate_random_bytes(buf.data(), attrs->key_bytes);
        const KeyId slot = arm_asm::detail::key_store_import(buf.data(), attrs->key_bytes);
        if (slot == 0U) { return std::unexpected(err_invalid_arg); }
        return slot;
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
            arm_asm::detail::key_store_destroy(id);
        }
        return ok;
    }
    [[nodiscard]]
    static auto export_key(KeyId id) // NOLINT(readability-function-size,readability-function-cognitive-complexity)
        -> std::expected<SecureBuffer, Status>
    {
        if (arm_asm::detail::rsa_key_id_is_rsa(id)) {
            using namespace arm_asm::detail;
            RsaKeyKind kind = RsaKeyKind::None; // NOLINT(misc-const-correctness)
            std::size_t bits = 0; // NOLINT(misc-const-correctness)
            const CryptoByte* key = nullptr;
            std::size_t key_len = 0; // NOLINT(misc-const-correctness)
            if (!rsa_key_store_get(id, &kind, &bits, &key, &key_len)) { return std::unexpected(err_invalid_arg); }
            if (kind != RsaKeyKind::Private) { return std::unexpected(err_invalid_arg); }
            SecureBuffer out(key_len);
            std::memcpy(out.data(), key, key_len);
            return out;
        }
        if (arm_asm::detail::ec_key_id_is_ec(id)) {
            using namespace arm_asm::detail;
            EcCurveId curve = EcCurveId::None; // NOLINT(misc-const-correctness)
            EcKeyKind kind  = EcKeyKind::None; // NOLINT(misc-const-correctness)
            const CryptoByte* key = nullptr;
            std::size_t key_len = 0; // NOLINT(misc-const-correctness)
            if (!ec_key_store_get(id, &curve, &kind, &key, &key_len)) { return std::unexpected(err_invalid_arg); }
            if (kind != EcKeyKind::Private) { return std::unexpected(err_invalid_arg); }
            SecureBuffer out(key_len);
            std::memcpy(out.data(), key, key_len);
            return out;
        }
        if (arm_asm::detail::pqc_key_id_is_pqc(id)) {
            const auto kv = arm_asm::detail::pqc_key_store_get_private(id);
            if (!kv) { return std::unexpected(err_invalid_arg); }
            SecureBuffer out(kv->data.size());
            std::memcpy(out.data(), kv->data.data(), kv->data.size());
            return out;
        }
        const CryptoByte* key = nullptr;
        std::size_t key_len = 0;
        if (!arm_asm::detail::key_store_get(id, &key, &key_len)) { return std::unexpected(err_invalid_arg); }
        SecureBuffer out(key_len);
        std::memcpy(out.data(), key, key_len);
        return out;
    }
    [[nodiscard]]
    static auto export_public_key(KeyId id) // NOLINT(readability-function-size,readability-function-cognitive-complexity)
        -> std::expected<SecureBuffer, Status>
    {
        using namespace arm_asm::detail;
        if (rsa_key_id_is_rsa(id)) {
            RsaKeyKind kind = RsaKeyKind::None; // NOLINT(misc-const-correctness)
            std::size_t bits = 0; // NOLINT(misc-const-correctness)
            const CryptoByte* key = nullptr;
            std::size_t key_len = 0; // NOLINT(misc-const-correctness)
            if (!rsa_key_store_get(id, &kind, &bits, &key, &key_len)) { return std::unexpected(err_invalid_arg); }
            if (kind != RsaKeyKind::Private) { return std::unexpected(err_invalid_arg); }
            SecureBuffer out(rsa_public_key_export_size(bits));
            std::size_t out_len = 0;
            if (!rsa_derive_public_key_der(key, key_len, out.data(), out.size(), &out_len)) {
                return std::unexpected(err_invalid_arg);
            }
            out.resize(out_len);
            return out;
        }
        if (pqc_key_id_is_pqc(id)) {
            const auto kv = pqc_key_store_get_public(id);
            if (!kv) { return std::unexpected(err_invalid_arg); }
            SecureBuffer out(kv->data.size());
            std::memcpy(out.data(), kv->data.data(), kv->data.size());
            return out;
        }
        if (!ec_key_id_is_ec(id)) { return std::unexpected(err_invalid_arg); }
        EcCurveId curve = EcCurveId::None; // NOLINT(misc-const-correctness)
        EcKeyKind kind  = EcKeyKind::None; // NOLINT(misc-const-correctness)
        const CryptoByte* key = nullptr;
        std::size_t key_len = 0; // NOLINT(misc-const-correctness)
        if (!ec_key_store_get(id, &curve, &kind, &key, &key_len)) { return std::unexpected(err_invalid_arg); }
        if (kind == EcKeyKind::Public) {
            SecureBuffer out(key_len);
            std::memcpy(out.data(), key, key_len);
            return out;
        }
        if (kind != EcKeyKind::Private) { return std::unexpected(err_invalid_arg); }
        if (curve == EcCurveId::P256) {
            constexpr std::size_t pk_len = p256_public_key_bytes;
            SecureBuffer out(pk_len);
            p256_compute_public_key(CByteSpan<p256_scalar_bytes>{key, p256_scalar_bytes},
                                    ByteSpan<p256_public_key_bytes>{out.data(), p256_public_key_bytes});
            return out;
        }
        if (curve == EcCurveId::P384) {
            constexpr std::size_t pk_len = p384_public_key_bytes;
            SecureBuffer out(pk_len);
            p384_compute_public_key(CByteSpan<p384_scalar_bytes>{key, p384_scalar_bytes},
                                    ByteSpan<p384_public_key_bytes>{out.data(), p384_public_key_bytes});
            return out;
        }
        if (curve == EcCurveId::P521) {
            constexpr std::size_t pk_len = p521_public_key_bytes;
            SecureBuffer out(pk_len);
            p521_compute_public_key(CByteSpan<p521_scalar_bytes>{key, p521_scalar_bytes},
                                    ByteSpan<p521_public_key_bytes>{out.data(), p521_public_key_bytes});
            return out;
        }
        return std::unexpected(err_invalid_arg);
    }
    // Internal helper used by mac_verify (old out-parameter interface).
    [[nodiscard]]
    static Status mac_compute_raw(  // NOLINT(readability-function-size)
                              KeyId id, Algorithm alg, // NOLINT(bugprone-easily-swappable-parameters)
                              const CryptoByte* msg, std::size_t msg_len,
                              CryptoByte* out, std::size_t out_size, std::size_t* out_len) {
        const CryptoByte* key = nullptr;
        std::size_t key_len = 0;
        if (!arm_asm::detail::key_store_get(id, &key, &key_len)) { return err_invalid_arg; }
        if (alg == alg_hmac(ShaVariant::Sha256)) {
            if (out_size < sha256_size_bytes) { return err_invalid_arg; }
            arm_asm::detail::hmac_sha256(key, key_len, msg, msg_len, ByteSpan<sha256_digest_bytes>{out, sha256_digest_bytes});
            *out_len = sha256_size_bytes;
            return ok;
        }
        if (alg == alg_hmac(ShaVariant::Sha512)) {
            if (out_size < sha512_size_bytes) { return err_invalid_arg; }
            arm_asm::detail::hmac_sha512(key, key_len, msg, msg_len, ByteSpan<sha512_digest_bytes>{out, sha512_digest_bytes});
            *out_len = sha512_size_bytes;
            return ok;
        }
        if (alg == alg_hmac(ShaVariant::Sha384)) {
            if (out_size < sha384_size_bytes) { return err_invalid_arg; }
            arm_asm::detail::hmac_sha384(key, key_len, msg, msg_len, ByteSpan<sha384_digest_bytes>{out, sha384_digest_bytes});
            *out_len = sha384_size_bytes;
            return ok;
        }
        if (alg == alg_hmac(ShaVariant::Sha3_256)) {
            if (out_size < sha3_256_size_bytes) { return err_invalid_arg; }
            arm_asm::detail::hmac_sha3_256(key, key_len, msg, msg_len, ByteSpan<sha3_256_digest_bytes>{out, sha3_256_digest_bytes});
            *out_len = sha3_256_size_bytes;
            return ok;
        }
        if (alg == alg_hmac(ShaVariant::Sha3_384)) {
            if (out_size < sha3_384_size_bytes) { return err_invalid_arg; }
            arm_asm::detail::hmac_sha3_384(key, key_len, msg, msg_len, ByteSpan<sha3_384_digest_bytes>{out, sha3_384_digest_bytes});
            *out_len = sha3_384_size_bytes;
            return ok;
        }
        if (alg == alg_hmac(ShaVariant::Sha3_512)) {
            if (out_size < sha3_512_size_bytes) { return err_invalid_arg; }
            arm_asm::detail::hmac_sha3_512(key, key_len, msg, msg_len, ByteSpan<sha3_512_digest_bytes>{out, sha3_512_digest_bytes});
            *out_len = sha3_512_size_bytes;
            return ok;
        }
        return err_invalid_arg;
    }
    [[nodiscard]]
    static auto mac_compute(  // NOLINT(readability-function-size)
                              KeyId id, Algorithm alg, // NOLINT(bugprone-easily-swappable-parameters)
                              const CByteVSpan msg)
        -> std::expected<SecureBuffer, Status>
    {
        SecureBuffer out(sha512_size_bytes);  // large enough for any HMAC output
        std::size_t out_len = 0;
        const auto s = mac_compute_raw(id, alg, msg.data(), msg.size(), out.data(), out.size(), &out_len);
        if (s != ok) {
            return std::unexpected(s);
        }
        out.resize(out_len);
        return out;
    }
    [[nodiscard]]
    static Status mac_verify(KeyId id, Algorithm alg,
                             const CByteVSpan msg,
                             const CByteVSpan mac) {
        // Compute the expected MAC then constant-time compare.
        FixedSecureBuffer<sha512_size_bytes> expected;
        std::size_t expected_len = 0;
        const Status s = mac_compute_raw(id, alg, msg.data(), msg.size(),
                                         expected.data(), expected.size(), &expected_len);
        if (s != ok) { return s; }
        if (mac.size() != expected_len) { return err_invalid_sig; }
        // Constant-time comparison.
        unsigned int diff = 0;
        for (std::size_t i = 0; i < expected_len; ++i) {
            diff |= static_cast<unsigned int>(mac[i]) ^ static_cast<unsigned int>(expected[i]);
        }
        return diff == 0U ? ok : err_invalid_sig;
    }
    [[nodiscard]]
    static auto aead_encrypt(  // NOLINT(readability-function-size)
                               KeyId id, Algorithm alg, // NOLINT(bugprone-easily-swappable-parameters)
                               const CByteVSpan nonce,
                               const CByteVSpan aad,
                               const CByteVSpan pt)
        -> std::expected<SecureBuffer, Status>
    {
        const CryptoByte* key = nullptr;
        std::size_t key_len = 0;
        if (!arm_asm::detail::key_store_get(id, &key, &key_len)) { return std::unexpected(err_invalid_arg); }
        if (key_len != 32) { return std::unexpected(err_invalid_arg); }
        if (alg == alg_aes_gcm()) {
            if (nonce.size() != arm_asm::detail::aes_gcm_iv_bytes) { return std::unexpected(err_invalid_arg); }
            if (pt.size() > SIZE_MAX - arm_asm::detail::aes_gcm_tag_bytes) { return std::unexpected(err_invalid_arg); }
            SecureBuffer out(pt.size() + arm_asm::detail::aes_gcm_tag_bytes);
            arm_asm::detail::aes256_gcm_encrypt(key, nonce.data(), aad.data(), aad.size(), pt.data(), pt.size(), out.data());
            return out;
        }
        if (alg == alg_chacha20_poly1305()) {
            if (nonce.size() != arm_asm::detail::chacha20_poly1305_nonce_bytes) { return std::unexpected(err_invalid_arg); }
            if (pt.size() > SIZE_MAX - arm_asm::detail::chacha20_poly1305_tag_bytes) { return std::unexpected(err_invalid_arg); }
            SecureBuffer out(pt.size() + arm_asm::detail::chacha20_poly1305_tag_bytes);
            arm_asm::detail::chacha20_poly1305_encrypt(key, nonce.data(), aad.data(), aad.size(), pt.data(), pt.size(), out.data());
            return out;
        }
        return std::unexpected(err_invalid_arg);
    }
    [[nodiscard]]
    static auto aead_decrypt(  // NOLINT(readability-function-size)
                               KeyId id, Algorithm alg, // NOLINT(bugprone-easily-swappable-parameters)
                               const CByteVSpan nonce,
                               const CByteVSpan aad,
                               const CByteVSpan ct)
        -> std::expected<SecureBuffer, Status>
    {
        const CryptoByte* key = nullptr;
        std::size_t key_len = 0;
        if (!arm_asm::detail::key_store_get(id, &key, &key_len)) { return std::unexpected(err_invalid_arg); }
        if (key_len != 32) { return std::unexpected(err_invalid_arg); }
        if (alg == alg_aes_gcm()) {
            if (nonce.size() != arm_asm::detail::aes_gcm_iv_bytes) { return std::unexpected(err_invalid_arg); }
            if (ct.size() < arm_asm::detail::aes_gcm_tag_bytes) { return std::unexpected(err_invalid_arg); }
            const std::size_t pt_len = ct.size() - arm_asm::detail::aes_gcm_tag_bytes;
            SecureBuffer out(pt_len);
            if (!arm_asm::detail::aes256_gcm_decrypt(key, nonce.data(), aad.data(), aad.size(), ct.data(), ct.size(), out.data())) {
                return std::unexpected(err_invalid_sig);
            }
            return out;
        }
        if (alg == alg_chacha20_poly1305()) {
            if (nonce.size() != arm_asm::detail::chacha20_poly1305_nonce_bytes) { return std::unexpected(err_invalid_arg); }
            if (ct.size() < arm_asm::detail::chacha20_poly1305_tag_bytes) { return std::unexpected(err_invalid_arg); }
            const std::size_t pt_len = ct.size() - arm_asm::detail::chacha20_poly1305_tag_bytes;
            SecureBuffer out(pt_len);
            if (!arm_asm::detail::chacha20_poly1305_decrypt(key, nonce.data(), aad.data(), aad.size(), ct.data(), ct.size(), out.data())) {
                return std::unexpected(err_invalid_sig);
            }
            return out;
        }
        return std::unexpected(err_invalid_arg);
    }
    // Internal helper used by the public sign_message wrapper.
    [[nodiscard]]
    static Status sign_message_raw(  // NOLINT(readability-function-cognitive-complexity,readability-function-size)
                               KeyId id, Algorithm alg, // NOLINT(bugprone-easily-swappable-parameters)
                               const CryptoByte* msg, std::size_t msg_len,
                               CryptoByte* sig, std::size_t sig_size, std::size_t* sig_len) {
        using namespace arm_asm::detail;
        if (alg == alg_rsa_pss()) {
            if (!rsa_key_id_is_rsa(id)) { return err_invalid_arg; }
            RsaKeyKind kind = RsaKeyKind::None; // NOLINT(misc-const-correctness)
            std::size_t bits = 0; // NOLINT(misc-const-correctness)
            const CryptoByte* key = nullptr;
            std::size_t key_len = 0; // NOLINT(misc-const-correctness)
            if (!rsa_key_store_get(id, &kind, &bits, &key, &key_len)) { return err_invalid_arg; }
            if (kind != RsaKeyKind::Private) { return err_invalid_arg; }
            if (!rsa_pss_sign(bits, key, key_len, msg, msg_len, sig, sig_size, sig_len)) {
                return err_invalid_arg;
            }
            return ok;
        }
#ifdef SAFE_CRYPTO_PQC_LIBOQS
        if ((alg & 0xFFF0U) == 0x0710U) {
            if (!pqc_key_id_is_pqc(id)) { return err_invalid_arg; }
            const auto kv = pqc_key_store_get_private(id);
            if (!kv || kv->type != PqcKeyType::MlDsaPrivate) { return err_invalid_arg; }
            const auto v = static_cast<MlDsaVariant>(kv->variant);
            if (alg != alg_ml_dsa(v)) { return err_invalid_arg; }
            if (sig_size < ml_dsa_signature_size(v)) { return err_invalid_arg; }
            if (!liboqs_pqc::ml_dsa_sign(v, kv->data.data(), kv->data.size(), msg, msg_len, sig, sig_size, sig_len)) {
                return err_invalid_arg;
            }
            return ok;
        }
#endif
        if (alg != alg_ecdsa()) { return err_invalid_arg; }
        if (!ec_key_id_is_ec(id)) { return err_invalid_arg; }
        EcCurveId curve = EcCurveId::None; // NOLINT(misc-const-correctness)
        EcKeyKind kind  = EcKeyKind::None; // NOLINT(misc-const-correctness)
        const CryptoByte* key = nullptr;
        std::size_t key_len = 0; // NOLINT(misc-const-correctness)
        if (!ec_key_store_get(id, &curve, &kind, &key, &key_len)) { return err_invalid_arg; }
        if (kind != EcKeyKind::Private) { return err_invalid_arg; }
        if (curve == EcCurveId::P256) {
            constexpr std::size_t sig_len_expected = p256_sig_bytes;
            if (sig_size < sig_len_expected) { return err_invalid_arg; }
            if (key_len != p256_scalar_bytes) { return err_invalid_arg; }
            ByteArray<sha256_digest_bytes> hash{};
            sha256(msg, msg_len, ByteSpan<sha256_digest_bytes>{hash.data(), sha256_digest_bytes});
            if (!p256_ecdsa_sign(CByteSpan<p256_scalar_bytes>{key, p256_scalar_bytes},
                                 CByteSpan<sha256_digest_bytes>{hash.data(), sha256_digest_bytes},
                                 ByteSpan<p256_sig_bytes>{sig, p256_sig_bytes})) { return err_invalid_arg; }
            *sig_len = sig_len_expected;
            return ok;
        }
        if (curve == EcCurveId::P384) {
            constexpr std::size_t sig_len_expected = p384_sig_bytes;
            if (sig_size < sig_len_expected) { return err_invalid_arg; }
            if (key_len != p384_scalar_bytes) { return err_invalid_arg; }
            ByteArray<sha384_digest_bytes> hash{};
            sha384(msg, msg_len, ByteSpan<sha384_digest_bytes>{hash.data(), sha384_digest_bytes});
            if (!p384_ecdsa_sign(CByteSpan<p384_scalar_bytes>{key, p384_scalar_bytes},
                                 CByteSpan<sha384_digest_bytes>{hash.data(), sha384_digest_bytes},
                                 ByteSpan<p384_sig_bytes>{sig, p384_sig_bytes})) { return err_invalid_arg; }
            *sig_len = sig_len_expected;
            return ok;
        }
        if (curve == EcCurveId::P521) {
            constexpr std::size_t sig_len_expected = p521_sig_bytes;
            if (sig_size < sig_len_expected) { return err_invalid_arg; }
            if (key_len != p521_scalar_bytes) { return err_invalid_arg; }
            ByteArray<sha512_digest_bytes> hash{};
            sha512(msg, msg_len, ByteSpan<sha512_digest_bytes>{hash.data(), sha512_digest_bytes});
            if (!p521_ecdsa_sign(CByteSpan<p521_scalar_bytes>{key, p521_scalar_bytes},
                                 CByteSpan<sha512_digest_bytes>{hash.data(), sha512_digest_bytes},
                                 ByteSpan<p521_sig_bytes>{sig, p521_sig_bytes})) { return err_invalid_arg; }
            *sig_len = sig_len_expected;
            return ok;
        }
        return err_invalid_arg;
    }
    [[nodiscard]]
    static auto sign_message(  // NOLINT(readability-function-cognitive-complexity,readability-function-size)
                               const KeyId id, const Algorithm alg, // NOLINT(bugprone-easily-swappable-parameters)
                               const CByteVSpan msg)
        -> std::expected<SecureBuffer, Status>
    {
        SecureBuffer sig(ml_dsa_87_signature_bytes);  // large enough for any signature
        std::size_t sig_len = 0;
        const auto s = sign_message_raw(id, alg, msg.data(), msg.size(), sig.data(), sig.size(), &sig_len);
        if (s != ok) {
            return std::unexpected(s);
        }
        sig.resize(sig_len);
        return sig;
    }
    [[nodiscard]]
    static Status verify_message(KeyId id, Algorithm alg, // NOLINT(readability-function-size,readability-function-cognitive-complexity,bugprone-easily-swappable-parameters)
                                 const CByteVSpan msg,
                                 const CByteVSpan sig) {
        using namespace arm_asm::detail;
        if (alg == alg_rsa_pss()) {
            if (!rsa_key_id_is_rsa(id)) { return err_invalid_arg; }
            RsaKeyKind kind = RsaKeyKind::None; // NOLINT(misc-const-correctness)
            std::size_t bits = 0; // NOLINT(misc-const-correctness)
            const CryptoByte* key = nullptr;
            std::size_t key_len = 0; // NOLINT(misc-const-correctness)
            if (!rsa_key_store_get(id, &kind, &bits, &key, &key_len)) { return err_invalid_arg; }
            if (kind != RsaKeyKind::Public) { return err_invalid_arg; }
            return rsa_pss_verify(bits, key, key_len, msg.data(), msg.size(), sig.data(), sig.size())
                ? ok : err_invalid_sig;
        }
#ifdef SAFE_CRYPTO_PQC_LIBOQS
        if ((alg & 0xFFF0U) == 0x0710U) {
            if (!pqc_key_id_is_pqc(id)) { return err_invalid_arg; }
            const auto kv = pqc_key_store_get_public(id);
            if (!kv || (kv->type != PqcKeyType::MlDsaPublic && kv->type != PqcKeyType::MlDsaPrivate)) {
                return err_invalid_arg;
            }
            const auto v = static_cast<MlDsaVariant>(kv->variant);
            if (alg != alg_ml_dsa(v)) { return err_invalid_arg; }
            return liboqs_pqc::ml_dsa_verify(v, kv->data.data(), kv->data.size(), msg.data(), msg.size(), sig.data(), sig.size())
                ? ok : err_invalid_sig;
        }
#endif
        if (alg != alg_ecdsa()) { return err_invalid_arg; }
        if (!ec_key_id_is_ec(id)) { return err_invalid_arg; }
        EcCurveId curve = EcCurveId::None; // NOLINT(misc-const-correctness)
        EcKeyKind kind  = EcKeyKind::None; // NOLINT(misc-const-correctness)
        const CryptoByte* key = nullptr;
        std::size_t key_len = 0; // NOLINT(misc-const-correctness)
        if (!ec_key_store_get(id, &curve, &kind, &key, &key_len)) { return err_invalid_arg; }
        if (kind != EcKeyKind::Public) { return err_invalid_arg; }
        if (curve == EcCurveId::P256) {
            if (sig.size() != p256_sig_bytes || key_len != p256_public_key_bytes) { return err_invalid_arg; }
            ByteArray<sha256_digest_bytes> hash{};
            sha256(msg.data(), msg.size(), ByteSpan<sha256_digest_bytes>{hash.data(), sha256_digest_bytes});
            return p256_ecdsa_verify(CByteSpan<p256_public_key_bytes>{key, p256_public_key_bytes},
                                     CByteSpan<sha256_digest_bytes>{hash.data(), sha256_digest_bytes},
                                     CByteSpan<p256_sig_bytes>{sig.data(), p256_sig_bytes}) ? ok : err_invalid_sig;
        }
        if (curve == EcCurveId::P384) {
            if (sig.size() != p384_sig_bytes || key_len != p384_public_key_bytes) { return err_invalid_arg; }
            ByteArray<sha384_digest_bytes> hash{};
            sha384(msg.data(), msg.size(), ByteSpan<sha384_digest_bytes>{hash.data(), sha384_digest_bytes});
            return p384_ecdsa_verify(CByteSpan<p384_public_key_bytes>{key, p384_public_key_bytes},
                                     CByteSpan<sha384_digest_bytes>{hash.data(), sha384_digest_bytes},
                                     CByteSpan<p384_sig_bytes>{sig.data(), p384_sig_bytes}) ? ok : err_invalid_sig;
        }
        if (curve == EcCurveId::P521) {
            if (sig.size() != p521_sig_bytes || key_len != p521_public_key_bytes) { return err_invalid_arg; }
            ByteArray<sha512_digest_bytes> hash{};
            sha512(msg.data(), msg.size(), ByteSpan<sha512_digest_bytes>{hash.data(), sha512_digest_bytes});
            return p521_ecdsa_verify(CByteSpan<p521_public_key_bytes>{key, p521_public_key_bytes},
                                     CByteSpan<sha512_digest_bytes>{hash.data(), sha512_digest_bytes},
                                     CByteSpan<p521_sig_bytes>{sig.data(), p521_sig_bytes}) ? ok : err_invalid_sig;
        }
        return err_invalid_arg;
    }
    [[nodiscard]]
    static auto raw_key_agreement(  // NOLINT(readability-function-cognitive-complexity,readability-function-size)
                                    Algorithm alg, KeyId id, // NOLINT(bugprone-easily-swappable-parameters)
                                    const CByteVSpan peer)
        -> std::expected<SecureBuffer, Status>
    {
        using namespace arm_asm::detail;
        if (alg != alg_ecdh()) { return std::unexpected(err_invalid_arg); }
        if (!ec_key_id_is_ec(id)) { return std::unexpected(err_invalid_arg); }
        EcCurveId curve = EcCurveId::None; // NOLINT(misc-const-correctness)
        EcKeyKind kind  = EcKeyKind::None; // NOLINT(misc-const-correctness)
        const CryptoByte* key = nullptr;
        std::size_t key_len = 0; // NOLINT(misc-const-correctness)
        if (!ec_key_store_get(id, &curve, &kind, &key, &key_len)) { return std::unexpected(err_invalid_arg); }
        if (kind != EcKeyKind::Private) { return std::unexpected(err_invalid_arg); }
        if (curve == EcCurveId::P256) {
            constexpr std::size_t pk_len = 65;
            constexpr std::size_t ss_len = p256_scalar_bytes;
            if (peer.size() != pk_len || peer[0] != 0x04U) { return std::unexpected(err_invalid_arg); }
            if (key_len != ss_len) { return std::unexpected(err_invalid_arg); }
            const Fe256 Qx = fe256_from_bytes(CByteSpan<p256_scalar_bytes>{peer.data() + 1,  p256_scalar_bytes});
            const Fe256 Qy = fe256_from_bytes(CByteSpan<p256_scalar_bytes>{peer.data() + 33, p256_scalar_bytes});
            if (!p256_validate_public_point(Qx, Qy)) { return std::unexpected(err_invalid_arg); }
            const P256Point Q{.X = Qx, .Y = Qy, .Z = fe256_one};
            const P256Point S = p256_to_affine(p256_scalar_mul(Q, CByteSpan<p256_scalar_bytes>{key, p256_scalar_bytes}));
            if (p256_point_is_identity(S)) { return std::unexpected(err_invalid_arg); }
            SecureBuffer out(ss_len);
            fe256_to_bytes(S.X, ByteSpan<p256_scalar_bytes>{out.data(), p256_scalar_bytes});
            return out;
        }
        if (curve == EcCurveId::P384) {
            constexpr std::size_t pk_len = 97;
            constexpr std::size_t ss_len = p384_scalar_bytes;
            if (peer.size() != pk_len || peer[0] != 0x04U) { return std::unexpected(err_invalid_arg); }
            if (key_len != ss_len) { return std::unexpected(err_invalid_arg); }
            const Fe384 Qx = fe384_from_bytes(CByteSpan<p384_scalar_bytes>{peer.data() + 1,  p384_scalar_bytes});
            const Fe384 Qy = fe384_from_bytes(CByteSpan<p384_scalar_bytes>{peer.data() + 49, p384_scalar_bytes});
            if (!p384_validate_public_point(Qx, Qy)) { return std::unexpected(err_invalid_arg); }
            const P384Point Q{.X = Qx, .Y = Qy, .Z = fe384_one};
            const P384Point S = p384_to_affine(p384_scalar_mul(Q, CByteSpan<p384_scalar_bytes>{key, p384_scalar_bytes}));
            if (p384_point_is_identity(S)) { return std::unexpected(err_invalid_arg); }
            SecureBuffer out(ss_len);
            fe384_to_bytes(S.X, ByteSpan<p384_scalar_bytes>{out.data(), p384_scalar_bytes});
            return out;
        }
        if (curve == EcCurveId::P521) {
            constexpr std::size_t pk_len = 133;
            constexpr std::size_t ss_len = p521_scalar_bytes;
            if (peer.size() != pk_len || peer[0] != 0x04U) { return std::unexpected(err_invalid_arg); }
            if (key_len != ss_len) { return std::unexpected(err_invalid_arg); }
            // Reject non-canonical P-521 encodings: top 7 bits of each coordinate's
            // first byte must be zero (521-bit field → only 1 bit in byte 0).
            if ((peer[1]  & 0xFEU) != 0U) { return std::unexpected(err_invalid_arg); }
            if ((peer[67] & 0xFEU) != 0U) { return std::unexpected(err_invalid_arg); }
            const Fe521 Qx = fe521_from_bytes(CByteSpan<p521_scalar_bytes>{peer.data() + 1,  p521_scalar_bytes});
            const Fe521 Qy = fe521_from_bytes(CByteSpan<p521_scalar_bytes>{peer.data() + 67, p521_scalar_bytes});
            if (!p521_validate_public_point(Qx, Qy)) { return std::unexpected(err_invalid_arg); }
            const P521Point Q{.X = Qx, .Y = Qy, .Z = fe521_one};
            const P521Point S = p521_to_affine(p521_scalar_mul(Q, CByteSpan<p521_scalar_bytes>{key, p521_scalar_bytes}));
            if (p521_point_is_identity(S)) { return std::unexpected(err_invalid_arg); }
            SecureBuffer out(ss_len);
            fe521_to_bytes(S.X, ByteSpan<p521_scalar_bytes>{out.data(), p521_scalar_bytes});
            return out;
        }
        return std::unexpected(err_invalid_arg);
    }
    [[nodiscard]]
    static auto asymmetric_encrypt(  // NOLINT(readability-function-size)
                                     KeyId id, Algorithm alg, // NOLINT(bugprone-easily-swappable-parameters)
                                     const CByteVSpan pt,
                                     const CByteVSpan salt)
        -> std::expected<SecureBuffer, Status>
    {
        using namespace arm_asm::detail;
        if (alg != alg_rsa_oaep()) { return std::unexpected(err_invalid_arg); }
        if (!rsa_key_id_is_rsa(id)) { return std::unexpected(err_invalid_arg); }
        RsaKeyKind kind = RsaKeyKind::None; // NOLINT(misc-const-correctness)
        std::size_t bits = 0; // NOLINT(misc-const-correctness)
        const CryptoByte* key = nullptr;
        std::size_t key_len = 0; // NOLINT(misc-const-correctness)
        if (!rsa_key_store_get(id, &kind, &bits, &key, &key_len)) { return std::unexpected(err_invalid_arg); }
        if (kind != RsaKeyKind::Public) { return std::unexpected(err_invalid_arg); }
        SecureBuffer out(rsa_oaep_encrypt_output_size(bits));
        std::size_t out_len = 0;
        if (!rsa_oaep_encrypt(bits, key, key_len, pt.data(), pt.size(), salt.data(), salt.size(), out.data(), out.size(), &out_len)) {
            return std::unexpected(err_invalid_arg);
        }
        out.resize(out_len);
        return out;
    }
    [[nodiscard]]
    static auto asymmetric_decrypt(  // NOLINT(readability-function-size)
                                     KeyId id, Algorithm alg, // NOLINT(bugprone-easily-swappable-parameters)
                                     const CByteVSpan ct,
                                     const CByteVSpan salt)
        -> std::expected<SecureBuffer, Status>
    {
        using namespace arm_asm::detail;
        if (alg != alg_rsa_oaep()) { return std::unexpected(err_invalid_arg); }
        if (!rsa_key_id_is_rsa(id)) { return std::unexpected(err_invalid_arg); }
        RsaKeyKind kind = RsaKeyKind::None; // NOLINT(misc-const-correctness)
        std::size_t bits = 0; // NOLINT(misc-const-correctness)
        const CryptoByte* key = nullptr;
        std::size_t key_len = 0; // NOLINT(misc-const-correctness)
        if (!rsa_key_store_get(id, &kind, &bits, &key, &key_len)) { return std::unexpected(err_invalid_arg); }
        if (kind != RsaKeyKind::Private) { return std::unexpected(err_invalid_arg); }
        SecureBuffer out(rsa_oaep_decrypt_output_size(bits));
        std::size_t out_len = 0;
        if (!rsa_oaep_decrypt(bits, key, key_len, ct.data(), ct.size(), salt.data(), salt.size(), out.data(), out.size(), &out_len)) {
            return std::unexpected(err_invalid_arg);
        }
        out.resize(out_len);
        return out;
    }
    [[nodiscard]]
    static auto hkdf_derive(
        const CByteVSpan ikm,
        const CByteVSpan salt,
        const CByteVSpan info,
        const std::size_t out_len, const bool expand_only)
        -> std::expected<SecureBuffer, Status>
    {
        using namespace arm_asm::detail;  // NOLINT(google-build-using-namespace)
        SecureBuffer output(out_len);

        if (expand_only) {
            if (hkdf_expand(ikm.data(), ikm.size(), info.data(), info.size(),
                            output.data(), out_len) != 0) {
                return std::unexpected(err_invalid_arg);
            }
            return output;
        }

        // Full HKDF: Extract then Expand.
        FixedSecureBuffer<hkdf_hash_len> prk;
        if (!salt.empty()) {
            hmac_sha384(salt.data(), salt.size(), ikm.data(), ikm.size(),
                        ByteSpan<hkdf_hash_len>{prk.data(), hkdf_hash_len});
        } else {
            const FixedSecureBuffer<hkdf_hash_len> zero_salt;
            hmac_sha384(zero_salt.data(), hkdf_hash_len, ikm.data(), ikm.size(),
                        ByteSpan<hkdf_hash_len>{prk.data(), hkdf_hash_len});
        }
        if (hkdf_expand(prk.data(), hkdf_hash_len, info.data(), info.size(),
                        output.data(), out_len) != 0) {
            return std::unexpected(err_invalid_arg);
        }
        return output;
    }

    // Algorithm tag encoding: low byte = base type, high byte = SHA variant index.
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
    static constexpr Algorithm alg_aes_gcm()           noexcept { return 0x0401U; }
    [[nodiscard]]
    static constexpr Algorithm alg_chacha20_poly1305() noexcept { return 0x0402U; }
    [[nodiscard]]
    static constexpr Algorithm alg_rsa_oaep()          noexcept { return 0x0601U; }
    [[nodiscard]]
    static constexpr Algorithm alg_rsa_pss()           noexcept { return 0x0602U; }

    // NOLINT(readability-named-parameter) — stub functions intentionally omit unused parameter names.
    [[nodiscard]]
    static KeyAttributes make_hmac_generate_attrs(ShaVariant /*v*/, std::size_t bits) noexcept { return {.key_bytes = bits / 8U}; }
    [[nodiscard]]
    static KeyAttributes make_hmac_verify_attrs(ShaVariant /*v*/, std::size_t bits)   noexcept { return {.key_bytes = bits / 8U}; }
    [[nodiscard]]
    static KeyAttributes make_ecdsa_generate_attrs(std::size_t bits)       noexcept {
        const auto curve = ec_curve_id_for_bits(bits);
        return {.key_bytes = ec_private_key_export_size(bits), .ec_curve = curve, .ec_kind = arm_asm::detail::EcKeyKind::Private};
    }
    [[nodiscard]]
    static KeyAttributes make_ecdsa_sign_attrs(std::size_t bits)           noexcept {
        const auto curve = ec_curve_id_for_bits(bits);
        return {.key_bytes = ec_private_key_export_size(bits), .ec_curve = curve, .ec_kind = arm_asm::detail::EcKeyKind::Private};
    }
    [[nodiscard]]
    static KeyAttributes make_ecdsa_verify_attrs(std::size_t bits)         noexcept {
        const auto curve = ec_curve_id_for_bits(bits);
        return {.key_bytes = ec_public_key_export_size(bits), .ec_curve = curve, .ec_kind = arm_asm::detail::EcKeyKind::Public};
    }
    [[nodiscard]]
    static KeyAttributes make_ecdh_generate_attrs(std::size_t bits)        noexcept {
        const auto curve = ec_curve_id_for_bits(bits);
        return {.key_bytes = ec_private_key_export_size(bits), .ec_curve = curve, .ec_kind = arm_asm::detail::EcKeyKind::Private};
    }
    [[nodiscard]]
    static KeyAttributes make_ecdh_agree_attrs(std::size_t bits)           noexcept {
        const auto curve = ec_curve_id_for_bits(bits);
        return {.key_bytes = ec_private_key_export_size(bits), .ec_curve = curve, .ec_kind = arm_asm::detail::EcKeyKind::Private};
    }
    [[nodiscard]]
    static KeyAttributes make_aes256_gcm_encrypt_attrs()                       noexcept { return {.key_bytes = aes256_key_size_bytes}; }
    [[nodiscard]]
    static KeyAttributes make_aes256_gcm_decrypt_attrs()                       noexcept { return {.key_bytes = aes256_key_size_bytes}; }
    [[nodiscard]]
    static KeyAttributes make_chacha20_poly1305_encrypt_attrs()                noexcept { return {.key_bytes = chacha20_key_size_bytes}; }
    [[nodiscard]]
    static KeyAttributes make_chacha20_poly1305_decrypt_attrs()                noexcept { return {.key_bytes = chacha20_key_size_bytes}; }
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
        if (bits == 256U) { return arm_asm::detail::EcCurveId::P256; }
        if (bits == 384U) { return arm_asm::detail::EcCurveId::P384; }
        return arm_asm::detail::EcCurveId::P521;
    }
    [[nodiscard]]
    static std::size_t ecdsa_sign_output_size(std::size_t bits)          noexcept { return ((bits + 7U) / 8U) * 2U; }  // 256→64, 384→96, 521→132
    [[nodiscard]]
    static std::size_t ecdh_shared_secret_size(std::size_t bits)         noexcept { return (bits + 7U) / 8U; }  // 256→32, 384→48, 521→66
    [[nodiscard]]
    static std::size_t ec_private_key_export_size(std::size_t bits)      noexcept { return (bits + 7U) / 8U; }  // 256→32, 384→48, 521→66
    [[nodiscard]]
    static std::size_t ec_public_key_export_size(std::size_t bits)       noexcept { return (((bits + 7U) / 8U) * 2U) + 1U; }  // 256→65, 384→97, 521→133
    [[nodiscard]]
    static std::size_t aes_gcm_encrypt_output_size(std::size_t pt_len)        noexcept { return pt_len <= SIZE_MAX - arm_asm::detail::aes_gcm_tag_bytes ? pt_len + arm_asm::detail::aes_gcm_tag_bytes : 0; }
    [[nodiscard]]
    static std::size_t aes_gcm_decrypt_output_size(std::size_t ct_len)        noexcept { return ct_len > arm_asm::detail::aes_gcm_tag_bytes ? ct_len - arm_asm::detail::aes_gcm_tag_bytes : 0; }
    [[nodiscard]]
    static std::size_t chacha20_encrypt_output_size(std::size_t pt_len) noexcept { return pt_len <= SIZE_MAX - arm_asm::detail::chacha20_poly1305_tag_bytes ? pt_len + arm_asm::detail::chacha20_poly1305_tag_bytes : 0; }
    [[nodiscard]]
    static std::size_t chacha20_decrypt_output_size(std::size_t ct_len) noexcept { return ct_len > arm_asm::detail::chacha20_poly1305_tag_bytes ? ct_len - arm_asm::detail::chacha20_poly1305_tag_bytes : 0; }
    [[nodiscard]]
    static std::size_t rsa_oaep_encrypt_output_size(std::size_t bits) noexcept {
        return bits / 8U;  // ciphertext = modulus size: 3072→384, 4096→512
    }
    [[nodiscard]]
    static std::size_t rsa_oaep_decrypt_output_size(std::size_t bits) noexcept {
        return bits / 8U;  // max plaintext ≤ modulus size
    }
    [[nodiscard]]
    static std::size_t rsa_pss_sign_output_size(std::size_t bits) noexcept {
        return bits / 8U;  // signature = modulus size: 3072→384, 4096→512
    }
    [[nodiscard]]
    static std::size_t rsa_private_key_export_size(std::size_t bits) noexcept {
        // PSA_KEY_EXPORT_RSA_KEY_PAIR_MAX_SIZE(bits) = 9*(bits/2/8+5+1)+14 = 9*(bits/16+6)+14
        return (9U * ((bits / 16U) + 6U)) + 14U;
    }
    [[nodiscard]]
    static std::size_t rsa_public_key_export_size(std::size_t bits) noexcept {
        // SubjectPublicKeyInfo overhead: ~38 bytes (AlgID + BIT STRING + SEQUENCE headers + sign pad)
        return (bits / 8U) + 50U;
    }

    // SLH-DSA — not yet implemented in ARM ASM backend; all operations return err_invalid_arg.
    [[nodiscard]]
    static Algorithm alg_slh_dsa(const SlhDsaVariant /*v*/) noexcept { return 0x0701U; }
    [[nodiscard]]
    static KeyAttributes make_slh_dsa_sign_attrs(const SlhDsaVariant /*v*/)     noexcept { return {}; }
    [[nodiscard]]
    static KeyAttributes make_slh_dsa_verify_attrs(const SlhDsaVariant /*v*/)   noexcept { return {}; }
    [[nodiscard]]
    static KeyAttributes make_slh_dsa_generate_attrs(const SlhDsaVariant /*v*/) noexcept { return {}; }
    [[nodiscard]]
    static std::size_t slh_dsa_sign_output_size(const SlhDsaVariant v)          noexcept { return slh_dsa_signature_size(v); }
    [[nodiscard]]
    static std::size_t slh_dsa_private_key_export_size(const SlhDsaVariant v)   noexcept { return slh_dsa_private_key_size(v); }
    [[nodiscard]]
    static std::size_t slh_dsa_public_key_export_size(const SlhDsaVariant v)    noexcept { return slh_dsa_public_key_size(v); }

    [[nodiscard]]
    static Algorithm alg_ml_dsa(const MlDsaVariant v) noexcept { return 0x0710U | static_cast<Algorithm>(v); }
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
    static Algorithm alg_ml_kem(const MlKemVariant v) noexcept { return 0x0800U | static_cast<Algorithm>(v); }
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
    static auto kem_encapsulate( // NOLINT(readability-function-size,readability-function-cognitive-complexity)
        const KeyId id, const Algorithm alg) // NOLINT(bugprone-easily-swappable-parameters)
        noexcept -> std::expected<KemEncapsulateResult, Status>
    {
#ifdef SAFE_CRYPTO_PQC_LIBOQS
        using arm_asm::detail::PqcKeyType;
        if ((alg & 0xFF00U) != 0x0800U) { return std::unexpected(err_invalid_arg); }
        if (!arm_asm::detail::pqc_key_id_is_pqc(id)) { return std::unexpected(err_invalid_arg); }
        const auto kv_enc = arm_asm::detail::pqc_key_store_get_public(id);
        if (!kv_enc || (kv_enc->type != PqcKeyType::MlKemPublic && kv_enc->type != PqcKeyType::MlKemPrivate)) {
            return std::unexpected(err_invalid_arg);
        }
        const auto v = static_cast<MlKemVariant>(kv_enc->variant);
        if (alg != alg_ml_kem(v)) { return std::unexpected(err_invalid_arg); }
        SecureBuffer ct_buf(ml_kem_ciphertext_size(v));
        SecureBuffer ss_buf(ml_kem_shared_secret_size(v));
        if (!liboqs_pqc::ml_kem_encaps(v, kv_enc->data.data(), kv_enc->data.size(),
                                        ct_buf.data(), ct_buf.size(),
                                        ss_buf.data(), ss_buf.size())) { return std::unexpected(err_invalid_arg); }
        return KemEncapsulateResult{.ciphertext = std::move(ct_buf), .shared_secret = std::move(ss_buf)};
#else
        (void)id; (void)alg;
        return std::unexpected(err_invalid_arg);
#endif
    }
    [[nodiscard]]
    static auto kem_decapsulate( // NOLINT(readability-function-size,readability-function-cognitive-complexity)
        const KeyId id, const Algorithm alg, // NOLINT(bugprone-easily-swappable-parameters)
        const CByteVSpan ciphertext)
        noexcept -> std::expected<SecureBuffer, Status>
    {
#ifdef SAFE_CRYPTO_PQC_LIBOQS
        using arm_asm::detail::PqcKeyType;
        if ((alg & 0xFF00U) != 0x0800U) { return std::unexpected(err_invalid_arg); }
        if (!arm_asm::detail::pqc_key_id_is_pqc(id)) { return std::unexpected(err_invalid_arg); }
        const auto kv_dec = arm_asm::detail::pqc_key_store_get_private(id);
        if (!kv_dec || kv_dec->type != PqcKeyType::MlKemPrivate) { return std::unexpected(err_invalid_arg); }
        const auto v = static_cast<MlKemVariant>(kv_dec->variant);
        if (alg != alg_ml_kem(v)) { return std::unexpected(err_invalid_arg); }
        SecureBuffer ss_buf(ml_kem_shared_secret_size(v));
        if (!liboqs_pqc::ml_kem_decaps(v, kv_dec->data.data(), kv_dec->data.size(),
                                        ciphertext.data(), ciphertext.size(),
                                        ss_buf.data(), ss_buf.size())) { return std::unexpected(err_invalid_arg); }
        return ss_buf;
#else
        (void)id; (void)alg;
        (void)ciphertext;
        return std::unexpected(err_invalid_arg);
#endif
    }
};
