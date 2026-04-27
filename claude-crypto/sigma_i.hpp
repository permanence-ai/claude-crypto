/*
Copyright Permanence AI, 2026. All rights reserved.

*/

#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <expected>

#include <psa/crypto.h>
#include <psa/crypto_sizes.h>
#include <psa/crypto_values.h>

#include "aead.hpp"
#include "crypto_error.hpp"
#include "defs.hpp"
#include "ecc.hpp"
#include "ecdh.hpp"
#include "mac.hpp"
#include "random.hpp"
#include "secure_buffer.hpp"
#include "sigma.hpp"


// Each party's identity bundle is AES-256-GCM encrypted in SIGMA-I.
constexpr std::size_t SIGMA_I_ENC_KEY_SIZE_BYTES = 32;


// Encrypted identity bundle carried in Msg2 and Msg3.
// Plaintext is: [uint16_be: id_pub_len][id_pub][uint16_be: sig_len][sig][48-byte mac]
struct SigmaIBundle {
    FixedSecureBuffer<AES_GCM_IV_SIZE_BYTES> iv;
    SecureBuffer                             ciphertext;
};

struct SigmaIMsg2 {
    SecureBuffer ephemeral_pub_r;
    SigmaIBundle bundle_r;
};

struct SigmaIMsg3 {
    SigmaIBundle bundle_i;
};

// Intermediate responder state passed from step 2 to step 4.
struct SigmaIResponderState {
    SigmaSessionKeys session_keys;
    SecureBuffer     enc_key_i;
};

struct SigmaIResponderRespondResult {
    SigmaIMsg2           msg2;
    SigmaIResponderState responder_state;
};

struct SigmaIInitiatorFinishResult {
    SigmaIMsg3       msg3;
    SigmaSessionKeys session_keys;
};


// Internal key material — not exposed outside this header.
struct SigmaIKeys {
    SecureBuffer mac_key;      // 48 bytes — HMAC-SHA-384
    SecureBuffer session_key;  // 32 bytes — application session key
    SecureBuffer enc_key_r;    // 32 bytes — AES-256 key for responder's Msg2 bundle
    SecureBuffer enc_key_i;    // 32 bytes — AES-256 key for initiator's Msg3 bundle
};


// Derives all four SIGMA-I keys from the raw ECDH shared secret via a single
// HKDF(SHA-384) operation.  Using full HKDF allows P-256's 32-byte shared
// secret to be used as IKM safely.
[[nodiscard]]
inline auto sigma_i_derive_keys(  // NOLINT(readability-function-cognitive-complexity)
    const SecureBuffer& shared_secret)
    -> std::expected<SigmaIKeys, CryptoError>
{
    constexpr std::size_t TOTAL_OUTPUT =
        SIGMA_MAC_KEY_SIZE_BYTES +
        SIGMA_SESSION_KEY_SIZE_BYTES +
        SIGMA_I_ENC_KEY_SIZE_BYTES +
        SIGMA_I_ENC_KEY_SIZE_BYTES;

    constexpr std::array<CRYPTO_BYTE, 7> INFO = {'s','i','g','m','a','-','i'};

    if (psa_crypto_init() != PSA_SUCCESS) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InitFailed,
            "PSA crypto init failed"));
    }

    psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attrs, PSA_KEY_TYPE_DERIVE);
    psa_set_key_bits(&attrs,
        static_cast<psa_key_bits_t>(shared_secret.size() * BITS_PER_BYTE));
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attrs, PSA_ALG_HKDF(PSA_ALG_SHA_384));

    mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
    if (psa_import_key(&attrs,
                       shared_secret.data(), shared_secret.size(),
                       &key_id) != PSA_SUCCESS) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyImportFailed,
            "SIGMA-I IKM import failed"));
    }

    psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;

    auto cleanup = [&]() {
        psa_key_derivation_abort(&op);
        psa_destroy_key(key_id);
    };

    if (psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_384)) != PSA_SUCCESS) {
        cleanup();
        return std::unexpected(CryptoError(
            CryptoErrorCode::KdfSetupFailed,
            "SIGMA-I HKDF setup failed"));
    }

    if (psa_key_derivation_input_key(
            &op, PSA_KEY_DERIVATION_INPUT_SECRET, key_id) != PSA_SUCCESS) {
        cleanup();
        return std::unexpected(CryptoError(
            CryptoErrorCode::KdfInputFailed,
            "SIGMA-I HKDF secret input failed"));
    }

    if (psa_key_derivation_input_bytes(
            &op, PSA_KEY_DERIVATION_INPUT_INFO,
            INFO.data(), INFO.size()) != PSA_SUCCESS) {
        cleanup();
        return std::unexpected(CryptoError(
            CryptoErrorCode::KdfInputFailed,
            "SIGMA-I HKDF info input failed"));
    }

    SecureBuffer output(TOTAL_OUTPUT);
    if (psa_key_derivation_output_bytes(
            &op, output.data(), output.size()) != PSA_SUCCESS) {
        cleanup();
        return std::unexpected(CryptoError(
            CryptoErrorCode::KdfOutputFailed,
            "SIGMA-I HKDF output failed"));
    }

    cleanup();

    auto slice = [&](const std::size_t offset, const std::size_t len) {
        SecureBuffer s(len);
        std::ranges::copy_n(
            output.begin() + static_cast<std::ptrdiff_t>(offset),
            static_cast<std::ptrdiff_t>(len),
            s.begin());
        return s;
    };

    constexpr std::size_t OFF_SESSION = SIGMA_MAC_KEY_SIZE_BYTES;
    constexpr std::size_t OFF_ENC_R   = OFF_SESSION + SIGMA_SESSION_KEY_SIZE_BYTES;
    constexpr std::size_t OFF_ENC_I   = OFF_ENC_R   + SIGMA_I_ENC_KEY_SIZE_BYTES;

    return SigmaIKeys{
        .mac_key      = slice(0,          SIGMA_MAC_KEY_SIZE_BYTES),
        .session_key  = slice(OFF_SESSION, SIGMA_SESSION_KEY_SIZE_BYTES),
        .enc_key_r    = slice(OFF_ENC_R,   SIGMA_I_ENC_KEY_SIZE_BYTES),
        .enc_key_i    = slice(OFF_ENC_I,   SIGMA_I_ENC_KEY_SIZE_BYTES),
    };
}


// Serialises identity_pub ‖ signature ‖ mac into a single buffer with
// 2-byte big-endian length prefixes on the variable-length fields.
[[nodiscard]]
inline auto sigma_i_serialize_bundle(
    const SecureBuffer&                          identity_pub,
    const SecureBuffer&                          signature,
    const FixedSecureBuffer<SIGMA_MAC_KEY_SIZE_BYTES>& mac)
    -> SecureBuffer
{
    const std::size_t total =
        2 + identity_pub.size() +
        2 + signature.size() +
        SIGMA_MAC_KEY_SIZE_BYTES;

    SecureBuffer out(total);
    std::size_t  off = 0;

    const auto pub_len = static_cast<uint16_t>(identity_pub.size());
    out[off++] = static_cast<CRYPTO_BYTE>(pub_len >> 8U);
    out[off++] = static_cast<CRYPTO_BYTE>(pub_len & 0xFFU);
    std::ranges::copy(identity_pub, out.begin() + static_cast<std::ptrdiff_t>(off));
    off += identity_pub.size();

    const auto sig_len = static_cast<uint16_t>(signature.size());
    out[off++] = static_cast<CRYPTO_BYTE>(sig_len >> 8U);
    out[off++] = static_cast<CRYPTO_BYTE>(sig_len & 0xFFU);
    std::ranges::copy(signature, out.begin() + static_cast<std::ptrdiff_t>(off));
    off += signature.size();

    std::ranges::copy(mac, out.begin() + static_cast<std::ptrdiff_t>(off));

    return out;
}


struct SigmaIBundlePlaintext {
    SecureBuffer                              identity_pub;
    SecureBuffer                              signature;
    FixedSecureBuffer<SIGMA_MAC_KEY_SIZE_BYTES> mac;
};


// Parses a serialised bundle.  Returns SigmaAuthFailed on malformed input so
// the caller doesn't need to distinguish parse errors from auth errors.
[[nodiscard]]
inline auto sigma_i_deserialize_bundle(const SecureBuffer& plaintext)
    -> std::expected<SigmaIBundlePlaintext, CryptoError>
{
    constexpr std::size_t MIN_SIZE = 2 + 1 + 2 + 1 + SIGMA_MAC_KEY_SIZE_BYTES;
    if (plaintext.size() < MIN_SIZE) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::SigmaAuthFailed,
            "SIGMA-I bundle too short"));
    }

    std::size_t off = 0;

    const std::size_t pub_len =
        (static_cast<std::size_t>(plaintext[off]) << 8U) |
         static_cast<std::size_t>(plaintext[off + 1]);
    off += 2;

    if (off + pub_len + 2 + SIGMA_MAC_KEY_SIZE_BYTES > plaintext.size()) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::SigmaAuthFailed,
            "SIGMA-I bundle identity_pub length invalid"));
    }

    SecureBuffer identity_pub(pub_len);
    std::ranges::copy_n(
        plaintext.begin() + static_cast<std::ptrdiff_t>(off),
        static_cast<std::ptrdiff_t>(pub_len),
        identity_pub.begin());
    off += pub_len;

    const std::size_t sig_len =
        (static_cast<std::size_t>(plaintext[off]) << 8U) |
         static_cast<std::size_t>(plaintext[off + 1]);
    off += 2;

    if (off + sig_len + SIGMA_MAC_KEY_SIZE_BYTES != plaintext.size()) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::SigmaAuthFailed,
            "SIGMA-I bundle signature length invalid"));
    }

    SecureBuffer signature(sig_len);
    std::ranges::copy_n(
        plaintext.begin() + static_cast<std::ptrdiff_t>(off),
        static_cast<std::ptrdiff_t>(sig_len),
        signature.begin());
    off += sig_len;

    FixedSecureBuffer<SIGMA_MAC_KEY_SIZE_BYTES> mac;
    std::ranges::copy_n(
        plaintext.begin() + static_cast<std::ptrdiff_t>(off),
        static_cast<std::ptrdiff_t>(SIGMA_MAC_KEY_SIZE_BYTES),
        mac.begin());

    return SigmaIBundlePlaintext{
        .identity_pub = std::move(identity_pub),
        .signature    = std::move(signature),
        .mac          = std::move(mac),
    };
}


// AES-256-GCM encrypt using a SecureBuffer key (PSA direct — aes256_gcm_encrypt
// requires FixedSecureBuffer<32> which can't be constructed from a SecureBuffer slice).
[[nodiscard]]
inline auto sigma_i_aes_gcm_encrypt(  // NOLINT(readability-function-cognitive-complexity)
    const SecureBuffer& key,
    const SecureBuffer& plaintext)
    -> std::expected<SigmaIBundle, CryptoError>
{
    constexpr std::size_t AES256_KEY_BITS = 256;

    if (psa_crypto_init() != PSA_SUCCESS) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InitFailed,
            "PSA crypto init failed"));
    }

    auto iv = random_bytes<AES_GCM_IV_SIZE_BYTES>();
    if (!iv.has_value()) {
        return std::unexpected(iv.error());
    }

    psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, AES256_KEY_BITS);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_GCM);

    mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
    if (psa_import_key(&attrs, key.data(), key.size(), &key_id) != PSA_SUCCESS) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyImportFailed,
            "SIGMA-I AES key import failed"));
    }

    const std::size_t output_size =
        PSA_AEAD_ENCRYPT_OUTPUT_SIZE(PSA_KEY_TYPE_AES, PSA_ALG_GCM, plaintext.size());
    SecureBuffer ciphertext(output_size);

    std::size_t ciphertext_length = 0;
    const psa_status_t status = psa_aead_encrypt(
        key_id, PSA_ALG_GCM,
        iv->data(), iv->size(),
        nullptr, 0,
        plaintext.data(), plaintext.size(),
        ciphertext.data(), ciphertext.size(),
        &ciphertext_length);

    psa_destroy_key(key_id);

    if (status != PSA_SUCCESS) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::EncryptionFailed,
            "SIGMA-I AES-GCM encryption failed"));
    }

    ciphertext.resize(ciphertext_length);
    return SigmaIBundle{
        .iv         = std::move(*iv),
        .ciphertext = std::move(ciphertext),
    };
}


[[nodiscard]]
inline auto sigma_i_aes_gcm_decrypt(  // NOLINT(readability-function-cognitive-complexity)
    const SecureBuffer& key,
    const SigmaIBundle& bundle)
    -> std::expected<SecureBuffer, CryptoError>
{
    constexpr std::size_t AES256_KEY_BITS = 256;

    if (psa_crypto_init() != PSA_SUCCESS) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InitFailed,
            "PSA crypto init failed"));
    }

    psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, AES256_KEY_BITS);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_GCM);

    mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
    if (psa_import_key(&attrs, key.data(), key.size(), &key_id) != PSA_SUCCESS) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyImportFailed,
            "SIGMA-I AES key import failed"));
    }

    const std::size_t plaintext_size =
        PSA_AEAD_DECRYPT_OUTPUT_SIZE(PSA_KEY_TYPE_AES, PSA_ALG_GCM, bundle.ciphertext.size());
    SecureBuffer plaintext(plaintext_size);

    std::size_t plaintext_length = 0;
    const psa_status_t status = psa_aead_decrypt(
        key_id, PSA_ALG_GCM,
        bundle.iv.data(), bundle.iv.size(),
        nullptr, 0,
        bundle.ciphertext.data(), bundle.ciphertext.size(),
        plaintext.data(), plaintext.size(),
        &plaintext_length);

    psa_destroy_key(key_id);

    if (status != PSA_SUCCESS) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::SigmaAuthFailed,
            "SIGMA-I bundle decryption failed"));
    }

    plaintext.resize(plaintext_length);
    return plaintext;
}


// Step 2 (Responder): receive Msg1, run ECDH, derive keys, encrypt identity bundle.
[[nodiscard]]
inline auto sigma_i_responder_respond(  // NOLINT(readability-function-cognitive-complexity)
    const SigmaMsg1&  msg1,
    const EccKeyPair& responder_identity,
    const EcCurve     curve)
    -> std::expected<SigmaIResponderRespondResult, CryptoError>
{
    auto eph_r = ecdh_generate_key(curve);
    if (!eph_r.has_value()) {
        return std::unexpected(eph_r.error());
    }

    auto shared_secret = ecdh_compute_shared_secret(
        *eph_r, curve, msg1.ephemeral_pub_i);
    if (!shared_secret.has_value()) {
        return std::unexpected(shared_secret.error());
    }

    auto keys = sigma_i_derive_keys(*shared_secret);
    if (!keys.has_value()) {
        return std::unexpected(keys.error());
    }

    // Sign eph_pub_i ‖ eph_pub_r.
    const auto sign_input = concat_buffers(msg1.ephemeral_pub_i, eph_r->public_key_der);
    auto sig_r = ecdsa_sign(responder_identity, curve, sign_input);
    if (!sig_r.has_value()) {
        return std::unexpected(sig_r.error());
    }

    // MAC over responder identity.
    auto mac_r = hmac_generate<ShaVariant::Sha384>(
        keys->mac_key, responder_identity.public_key_der);
    if (!mac_r.has_value()) {
        return std::unexpected(mac_r.error());
    }

    // Encrypt the identity bundle.
    const auto plaintext_r = sigma_i_serialize_bundle(
        responder_identity.public_key_der, *sig_r, *mac_r);
    auto bundle_r = sigma_i_aes_gcm_encrypt(keys->enc_key_r, plaintext_r);
    if (!bundle_r.has_value()) {
        return std::unexpected(bundle_r.error());
    }

    SecureBuffer eph_pub_r_copy(eph_r->public_key_der.size());
    std::ranges::copy(eph_r->public_key_der, eph_pub_r_copy.begin());

    return SigmaIResponderRespondResult{
        .msg2 = SigmaIMsg2{
            .ephemeral_pub_r = std::move(eph_pub_r_copy),
            .bundle_r        = std::move(*bundle_r),
        },
        .responder_state = SigmaIResponderState{
            .session_keys = SigmaSessionKeys{
                .mac_key     = std::move(keys->mac_key),
                .session_key = std::move(keys->session_key),
            },
            .enc_key_i = std::move(keys->enc_key_i),
        },
    };
}


// Step 3 (Initiator): decrypt and verify Msg2, encrypt own identity bundle.
[[nodiscard]]
inline auto sigma_i_initiator_finish(  // NOLINT(readability-function-cognitive-complexity)
    SigmaInitiatorState        state,
    const SigmaIMsg2&          msg2,
    const EccKeyPair&          initiator_identity,
    const SecureBuffer&        expected_responder_pub,
    const EcCurve              curve)
    -> std::expected<SigmaIInitiatorFinishResult, CryptoError>
{
    auto shared_secret = ecdh_compute_shared_secret(
        state.ephemeral_key_pair, curve, msg2.ephemeral_pub_r);
    if (!shared_secret.has_value()) {
        return std::unexpected(shared_secret.error());
    }

    auto keys = sigma_i_derive_keys(*shared_secret);
    if (!keys.has_value()) {
        return std::unexpected(keys.error());
    }

    // Decrypt the responder bundle.
    auto plaintext_r = sigma_i_aes_gcm_decrypt(keys->enc_key_r, msg2.bundle_r);
    if (!plaintext_r.has_value()) {
        return std::unexpected(plaintext_r.error());
    }

    auto bundle_r = sigma_i_deserialize_bundle(*plaintext_r);
    if (!bundle_r.has_value()) {
        return std::unexpected(bundle_r.error());
    }

    // Verify responder identity matches expected.
    if (bundle_r->identity_pub.size() != expected_responder_pub.size() ||
        !std::ranges::equal(bundle_r->identity_pub, expected_responder_pub)) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::SigmaAuthFailed,
            "Responder identity mismatch"));
    }

    // Verify HMAC over responder identity.
    auto mac_ok = hmac_verify<ShaVariant::Sha384>(
        keys->mac_key, bundle_r->identity_pub, bundle_r->mac);
    if (!mac_ok.has_value()) {
        return std::unexpected(mac_ok.error());
    }
    if (!*mac_ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::SigmaAuthFailed,
            "Responder MAC verification failed"));
    }

    // Verify responder signature.
    const auto sign_input = concat_buffers(state.ephemeral_pub_i, msg2.ephemeral_pub_r);
    EccKeyPair responder_pub_only{
        .private_key_der = SecureBuffer(0),
        .public_key_der  = [&] {
            SecureBuffer b(bundle_r->identity_pub.size());
            std::ranges::copy(bundle_r->identity_pub, b.begin());
            return b;
        }(),
    };
    auto sig_ok = ecdsa_verify(responder_pub_only, curve, sign_input, bundle_r->signature);
    if (!sig_ok.has_value()) {
        return std::unexpected(sig_ok.error());
    }
    if (!*sig_ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::SigmaAuthFailed,
            "Responder signature verification failed"));
    }

    // Sign and MAC for the initiator bundle.
    auto sig_i = ecdsa_sign(initiator_identity, curve, sign_input);
    if (!sig_i.has_value()) {
        return std::unexpected(sig_i.error());
    }

    auto mac_i = hmac_generate<ShaVariant::Sha384>(
        keys->mac_key, initiator_identity.public_key_der);
    if (!mac_i.has_value()) {
        return std::unexpected(mac_i.error());
    }

    // Encrypt the initiator bundle with K_enc_i.
    const auto plaintext_i = sigma_i_serialize_bundle(
        initiator_identity.public_key_der, *sig_i, *mac_i);
    auto bundle_i = sigma_i_aes_gcm_encrypt(keys->enc_key_i, plaintext_i);
    if (!bundle_i.has_value()) {
        return std::unexpected(bundle_i.error());
    }

    return SigmaIInitiatorFinishResult{
        .msg3 = SigmaIMsg3{ .bundle_i = std::move(*bundle_i) },
        .session_keys = SigmaSessionKeys{
            .mac_key     = std::move(keys->mac_key),
            .session_key = std::move(keys->session_key),
        },
    };
}


// Step 4 (Responder): decrypt and verify Msg3.
[[nodiscard]]
inline auto sigma_i_responder_finish(  // NOLINT(readability-function-cognitive-complexity)
    const SigmaIMsg3&           msg3,
    const SigmaIResponderState& responder_state,
    const SigmaMsg1&            msg1,
    const SigmaIMsg2&           msg2,
    const SecureBuffer&         expected_initiator_pub,
    const EcCurve               curve)
    -> std::expected<bool, CryptoError>
{
    // Decrypt the initiator bundle with K_enc_i.
    auto plaintext_i = sigma_i_aes_gcm_decrypt(responder_state.enc_key_i, msg3.bundle_i);
    if (!plaintext_i.has_value()) {
        return false;
    }

    auto bundle_i = sigma_i_deserialize_bundle(*plaintext_i);
    if (!bundle_i.has_value()) {
        return false;
    }

    // Verify initiator identity.
    if (bundle_i->identity_pub.size() != expected_initiator_pub.size() ||
        !std::ranges::equal(bundle_i->identity_pub, expected_initiator_pub)) {
        return false;
    }

    // Verify HMAC.
    auto mac_ok = hmac_verify<ShaVariant::Sha384>(
        responder_state.session_keys.mac_key, bundle_i->identity_pub, bundle_i->mac);
    if (!mac_ok.has_value()) {
        return std::unexpected(mac_ok.error());
    }
    if (!*mac_ok) {
        return false;
    }

    // Verify initiator signature.
    const auto sign_input = concat_buffers(msg1.ephemeral_pub_i, msg2.ephemeral_pub_r);
    EccKeyPair initiator_pub_only{
        .private_key_der = SecureBuffer(0),
        .public_key_der  = [&] {
            SecureBuffer b(bundle_i->identity_pub.size());
            std::ranges::copy(bundle_i->identity_pub, b.begin());
            return b;
        }(),
    };
    auto sig_ok = ecdsa_verify(initiator_pub_only, curve, sign_input, bundle_i->signature);
    if (!sig_ok.has_value()) {
        return std::unexpected(sig_ok.error());
    }

    return *sig_ok;
}
