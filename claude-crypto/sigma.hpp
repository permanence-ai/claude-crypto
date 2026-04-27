/*
Copyright Permanence AI, 2026. All rights reserved.

*/

#pragma once

#include <algorithm>
#include <cstddef>
#include <expected>

#include <psa/crypto.h>
#include <psa/crypto_values.h>

#include "crypto_error.hpp"
#include "defs.hpp"
#include "ecc.hpp"
#include "ecdh.hpp"
#include "mac.hpp"
#include "secure_buffer.hpp"


// Key sizes derived from the shared secret via HKDF-Expand.
constexpr std::size_t SIGMA_MAC_KEY_SIZE_BYTES     = 48;   // HMAC-SHA-384 key
constexpr std::size_t SIGMA_SESSION_KEY_SIZE_BYTES = 32;   // AES-256 / ChaCha20 key


struct SigmaMsg1 {
    SecureBuffer ephemeral_pub_i;
};

struct SigmaMsg2 {
    SecureBuffer                              ephemeral_pub_r;
    SecureBuffer                              identity_pub_r;
    SecureBuffer                              signature_r;
    FixedSecureBuffer<SIGMA_MAC_KEY_SIZE_BYTES> mac_r;
};

struct SigmaMsg3 {
    SecureBuffer                              identity_pub_i;
    SecureBuffer                              signature_i;
    FixedSecureBuffer<SIGMA_MAC_KEY_SIZE_BYTES> mac_i;
};

struct SigmaSessionKeys {
    SecureBuffer mac_key;
    SecureBuffer session_key;
};

// Opaque initiator state carried between sigma_initiator_init and sigma_initiator_finish.
// Holds the ephemeral private key — non-copyable.
struct SigmaInitiatorState {
    EccKeyPair   ephemeral_key_pair;
    SecureBuffer ephemeral_pub_i;
};

struct SigmaInitiatorInitResult {
    SigmaMsg1           msg1;
    SigmaInitiatorState state;
};

struct SigmaResponderRespondResult {
    SigmaMsg2         msg2;
    SigmaSessionKeys  session_keys;
};

struct SigmaInitiatorFinishResult {
    SigmaMsg3        msg3;
    SigmaSessionKeys session_keys;
};


// Concatenates two buffers into a single SecureBuffer.
[[nodiscard]]
inline auto concat_buffers(const SecureBuffer& a, const SecureBuffer& b) -> SecureBuffer {
    SecureBuffer out(a.size() + b.size());
    std::ranges::copy(a, out.begin());
    std::ranges::copy(b, out.begin() + static_cast<std::ptrdiff_t>(a.size()));
    return out;
}


// Derives K_mac (48 bytes) and K_session (32 bytes) from the raw ECDH shared
// secret using a single HKDF (extract+expand, SHA-384) operation.  Using full
// HKDF rather than HKDF-Expand alone allows shared secrets shorter than the
// hash output size (e.g. the 32-byte P-256 x-coordinate) to be safely used as
// input keying material.
[[nodiscard]]
inline auto sigma_derive_keys(  // NOLINT(readability-function-cognitive-complexity)
    const SecureBuffer& shared_secret)
    -> std::expected<SigmaSessionKeys, CryptoError>
{
    constexpr std::size_t TOTAL_OUTPUT = SIGMA_MAC_KEY_SIZE_BYTES + SIGMA_SESSION_KEY_SIZE_BYTES;

    // "sigma" as context info distinguishes these keys from any other HKDF use.
    constexpr std::array<CRYPTO_BYTE, 5> INFO = {'s','i','g','m','a'};

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
            "SIGMA IKM import failed"));
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
            "SIGMA HKDF setup failed"));
    }

    if (psa_key_derivation_input_key(
            &op, PSA_KEY_DERIVATION_INPUT_SECRET, key_id) != PSA_SUCCESS) {
        cleanup();
        return std::unexpected(CryptoError(
            CryptoErrorCode::KdfInputFailed,
            "SIGMA HKDF secret input failed"));
    }

    if (psa_key_derivation_input_bytes(
            &op, PSA_KEY_DERIVATION_INPUT_INFO,
            INFO.data(), INFO.size()) != PSA_SUCCESS) {
        cleanup();
        return std::unexpected(CryptoError(
            CryptoErrorCode::KdfInputFailed,
            "SIGMA HKDF info input failed"));
    }

    SecureBuffer output(TOTAL_OUTPUT);
    if (psa_key_derivation_output_bytes(
            &op, output.data(), output.size()) != PSA_SUCCESS) {
        cleanup();
        return std::unexpected(CryptoError(
            CryptoErrorCode::KdfOutputFailed,
            "SIGMA HKDF output failed"));
    }

    cleanup();

    SecureBuffer mac_key(SIGMA_MAC_KEY_SIZE_BYTES);
    SecureBuffer session_key(SIGMA_SESSION_KEY_SIZE_BYTES);
    std::ranges::copy_n(output.begin(), static_cast<std::ptrdiff_t>(SIGMA_MAC_KEY_SIZE_BYTES),
                        mac_key.begin());
    std::ranges::copy_n(output.begin() + static_cast<std::ptrdiff_t>(SIGMA_MAC_KEY_SIZE_BYTES),
                        static_cast<std::ptrdiff_t>(SIGMA_SESSION_KEY_SIZE_BYTES),
                        session_key.begin());

    return SigmaSessionKeys{
        .mac_key     = std::move(mac_key),
        .session_key = std::move(session_key),
    };
}


// Step 1 (Initiator): generate ephemeral key pair, produce Msg1.
[[nodiscard]]
inline auto sigma_initiator_begin(const EcCurve curve)
    -> std::expected<SigmaInitiatorInitResult, CryptoError>
{
    auto eph = ecdh_generate_key(curve);
    if (!eph.has_value()) {
        return std::unexpected(eph.error());
    }

    // Keep a copy of the public key in state for use in step 3.
    SecureBuffer pub_for_msg(eph->public_key_der.size());
    SecureBuffer pub_for_state(eph->public_key_der.size());
    std::ranges::copy(eph->public_key_der, pub_for_msg.begin());
    std::ranges::copy(eph->public_key_der, pub_for_state.begin());

    return SigmaInitiatorInitResult{
        .msg1  = SigmaMsg1{ .ephemeral_pub_i = std::move(pub_for_msg) },
        .state = SigmaInitiatorState{
            .ephemeral_key_pair = std::move(*eph),
            .ephemeral_pub_i    = std::move(pub_for_state),
        },
    };
}


// Step 2 (Responder): receive Msg1, run ECDH, sign, MAC, produce Msg2 + session keys.
[[nodiscard]]
inline auto sigma_responder_respond(  // NOLINT(readability-function-cognitive-complexity)
    const SigmaMsg1&  msg1,
    const EccKeyPair& responder_identity,
    const EcCurve     curve)
    -> std::expected<SigmaResponderRespondResult, CryptoError>
{
    // Generate responder ephemeral key pair.
    auto eph_r = ecdh_generate_key(curve);
    if (!eph_r.has_value()) {
        return std::unexpected(eph_r.error());
    }

    // ECDH with initiator's ephemeral public key.
    auto shared_secret = ecdh_compute_shared_secret(
        *eph_r, curve, msg1.ephemeral_pub_i);
    if (!shared_secret.has_value()) {
        return std::unexpected(shared_secret.error());
    }

    // Derive K_mac and K_session.
    auto keys = sigma_derive_keys(*shared_secret);
    if (!keys.has_value()) {
        return std::unexpected(keys.error());
    }

    // Sign eph_pub_i ‖ eph_pub_r with responder long-term identity key.
    const auto sign_input = concat_buffers(msg1.ephemeral_pub_i, eph_r->public_key_der);
    auto sig_r = ecdsa_sign(responder_identity, curve, sign_input);
    if (!sig_r.has_value()) {
        return std::unexpected(sig_r.error());
    }

    // MAC over responder's long-term public key using K_mac.
    // K_mac is SecureBuffer (48 bytes); hmac_generate accepts any SecureBufferLike.
    auto mac_r = hmac_generate<ShaVariant::Sha384>(
        keys->mac_key, responder_identity.public_key_der);
    if (!mac_r.has_value()) {
        return std::unexpected(mac_r.error());
    }

    SecureBuffer eph_pub_r_copy(eph_r->public_key_der.size());
    std::ranges::copy(eph_r->public_key_der, eph_pub_r_copy.begin());

    SecureBuffer identity_pub_r_copy(responder_identity.public_key_der.size());
    std::ranges::copy(responder_identity.public_key_der, identity_pub_r_copy.begin());

    return SigmaResponderRespondResult{
        .msg2 = SigmaMsg2{
            .ephemeral_pub_r = std::move(eph_pub_r_copy),
            .identity_pub_r  = std::move(identity_pub_r_copy),
            .signature_r     = std::move(*sig_r),
            .mac_r           = std::move(*mac_r),
        },
        .session_keys = std::move(*keys),
    };
}


// Step 3 (Initiator): verify Msg2, sign, MAC, produce Msg3 + session keys.
[[nodiscard]]
inline auto sigma_initiator_finish(  // NOLINT(readability-function-cognitive-complexity)
    SigmaInitiatorState        state,
    const SigmaMsg2&           msg2,
    const EccKeyPair&          initiator_identity,
    const SecureBuffer&        expected_responder_pub,
    const EcCurve              curve)
    -> std::expected<SigmaInitiatorFinishResult, CryptoError>
{
    // ECDH with responder's ephemeral public key.
    auto shared_secret = ecdh_compute_shared_secret(
        state.ephemeral_key_pair, curve, msg2.ephemeral_pub_r);
    if (!shared_secret.has_value()) {
        return std::unexpected(shared_secret.error());
    }

    auto keys = sigma_derive_keys(*shared_secret);
    if (!keys.has_value()) {
        return std::unexpected(keys.error());
    }

    // Verify that the responder identity in Msg2 matches the expected public key.
    if (msg2.identity_pub_r.size() != expected_responder_pub.size() ||
        !std::ranges::equal(msg2.identity_pub_r, expected_responder_pub)) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::SigmaAuthFailed,
            "Responder identity mismatch"));
    }

    // Verify HMAC over responder identity.
    auto mac_ok = hmac_verify<ShaVariant::Sha384>(
        keys->mac_key, msg2.identity_pub_r, msg2.mac_r);
    if (!mac_ok.has_value()) {
        return std::unexpected(mac_ok.error());
    }
    if (!*mac_ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::SigmaAuthFailed,
            "Responder MAC verification failed"));
    }

    // Verify responder signature over eph_pub_i ‖ eph_pub_r.
    const auto sign_input = concat_buffers(state.ephemeral_pub_i, msg2.ephemeral_pub_r);

    // Build a key pair with only the responder public key for verification.
    EccKeyPair responder_pub_only{
        .private_key_der = SecureBuffer(0),
        .public_key_der  = [&] {
            SecureBuffer b(msg2.identity_pub_r.size());
            std::ranges::copy(msg2.identity_pub_r, b.begin());
            return b;
        }(),
    };

    auto sig_ok = ecdsa_verify(responder_pub_only, curve, sign_input, msg2.signature_r);
    if (!sig_ok.has_value()) {
        return std::unexpected(sig_ok.error());
    }
    if (!*sig_ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::SigmaAuthFailed,
            "Responder signature verification failed"));
    }

    // Sign eph_pub_i ‖ eph_pub_r with initiator long-term identity key.
    auto sig_i = ecdsa_sign(initiator_identity, curve, sign_input);
    if (!sig_i.has_value()) {
        return std::unexpected(sig_i.error());
    }

    // MAC over initiator's long-term public key using K_mac.
    auto mac_i = hmac_generate<ShaVariant::Sha384>(
        keys->mac_key, initiator_identity.public_key_der);
    if (!mac_i.has_value()) {
        return std::unexpected(mac_i.error());
    }

    SecureBuffer identity_pub_i_copy(initiator_identity.public_key_der.size());
    std::ranges::copy(initiator_identity.public_key_der, identity_pub_i_copy.begin());

    return SigmaInitiatorFinishResult{
        .msg3 = SigmaMsg3{
            .identity_pub_i = std::move(identity_pub_i_copy),
            .signature_i    = std::move(*sig_i),
            .mac_i          = std::move(*mac_i),
        },
        .session_keys = std::move(*keys),
    };
}


// Step 4 (Responder): verify Msg3. Returns false on auth failure, error on fault.
[[nodiscard]]
inline auto sigma_responder_finish(  // NOLINT(readability-function-cognitive-complexity)
    const SigmaMsg3&         msg3,
    const SigmaSessionKeys&  session_keys,
    const SigmaMsg1&         msg1,
    const SigmaMsg2&         msg2,
    const SecureBuffer&      expected_initiator_pub,
    const EcCurve            curve)
    -> std::expected<bool, CryptoError>
{
    // Verify initiator identity matches expected.
    if (msg3.identity_pub_i.size() != expected_initiator_pub.size() ||
        !std::ranges::equal(msg3.identity_pub_i, expected_initiator_pub)) {
        return false;
    }

    // Verify HMAC over initiator identity.
    auto mac_ok = hmac_verify<ShaVariant::Sha384>(
        session_keys.mac_key, msg3.identity_pub_i, msg3.mac_i);
    if (!mac_ok.has_value()) {
        return std::unexpected(mac_ok.error());
    }
    if (!*mac_ok) {
        return false;
    }

    // Verify initiator signature over eph_pub_i ‖ eph_pub_r.
    const auto sign_input = concat_buffers(msg1.ephemeral_pub_i, msg2.ephemeral_pub_r);

    EccKeyPair initiator_pub_only{
        .private_key_der = SecureBuffer(0),
        .public_key_der  = [&] {
            SecureBuffer b(msg3.identity_pub_i.size());
            std::ranges::copy(msg3.identity_pub_i, b.begin());
            return b;
        }(),
    };

    auto sig_ok = ecdsa_verify(initiator_pub_only, curve, sign_input, msg3.signature_i);
    if (!sig_ok.has_value()) {
        return std::unexpected(sig_ok.error());
    }

    return *sig_ok;
}
