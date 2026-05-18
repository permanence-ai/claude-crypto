// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <algorithm>
#include <cstddef>
#include <expected>

#include "crypto_error.hpp"
#include "defs.hpp"
#include "ecc.hpp"
#include "ecdh.hpp"
#include "mac.hpp"
#include "psa_backend.hpp"
#include "secure_buffer.hpp"


// Key sizes derived from the shared secret via HKDF-Expand.
constexpr std::size_t sigma_mac_key_size_bytes     = 48;   // HMAC-SHA-384 key
constexpr std::size_t sigma_session_key_size_bytes = 32;   // AES-256 / ChaCha20 key


struct SigmaMsg1 {
    SecureBuffer ephemeral_pub_i;
};

struct SigmaMsg2 {
    SecureBuffer                              ephemeral_pub_r;
    SecureBuffer                              identity_pub_r;
    SecureBuffer                              signature_r;
    FixedSecureBuffer<sigma_mac_key_size_bytes> mac_r;
};

struct SigmaMsg3 {
    SecureBuffer                              identity_pub_i;
    SecureBuffer                              signature_i;
    FixedSecureBuffer<sigma_mac_key_size_bytes> mac_i;
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


namespace detail {
[[nodiscard]]
inline auto concat_buffers(const SecureBuffer& a, const SecureBuffer& b) -> SecureBuffer {
    SecureBuffer out(a.size() + b.size());
    std::ranges::copy(a, out.begin());
    std::ranges::copy(b, out.begin() + static_cast<std::ptrdiff_t>(a.size()));
    return out;
}
}  // namespace detail


// Derives K_mac (48 bytes) and K_session (32 bytes) from the raw ECDH shared
// secret using a single HKDF (extract+expand, SHA-384) operation.  Using full
// HKDF rather than HKDF-Expand alone allows shared secrets shorter than the
// hash output size (e.g. the 32-byte P-256 x-coordinate) to be safely used as
// input keying material.
template<CryptoProvider Provider = DefaultProvider>
[[nodiscard]]
auto sigma_derive_keys_impl(
    const SecureBuffer& shared_secret)
    -> std::expected<SigmaSessionKeys, CryptoError>
{
    constexpr std::size_t total_output = sigma_mac_key_size_bytes + sigma_session_key_size_bytes;
    constexpr ByteArray<5> info = {'s','i','g','m','a'};

    if (Provider::crypto_init() != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InitFailed,
            "PSA crypto init failed"));
    }

    auto result = Provider::hkdf_derive(
        CByteVSpan{shared_secret.data(), shared_secret.size()},
        CByteVSpan{},
        CByteVSpan{info.data(), info.size()},
        total_output, false);

    if (!result.has_value()) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KdfOutputFailed,
            "SIGMA HKDF derivation failed"));
    }
    const SecureBuffer& output = result.value();

    SecureBuffer mac_key(sigma_mac_key_size_bytes);
    SecureBuffer session_key(sigma_session_key_size_bytes);
    std::ranges::copy_n(output.begin(), static_cast<std::ptrdiff_t>(sigma_mac_key_size_bytes),
                        mac_key.begin());
    std::ranges::copy_n(output.begin() + static_cast<std::ptrdiff_t>(sigma_mac_key_size_bytes),
                        static_cast<std::ptrdiff_t>(sigma_session_key_size_bytes),
                        session_key.begin());

    return SigmaSessionKeys{
        .mac_key     = std::move(mac_key),
        .session_key = std::move(session_key),
    };
}

[[nodiscard]]
inline auto sigma_derive_keys(const SecureBuffer& shared_secret)
    -> std::expected<SigmaSessionKeys, CryptoError>
{
    return sigma_derive_keys_impl(shared_secret);
}


// Step 1 (Initiator): generate ephemeral key pair, produce Msg1.
template<CryptoProvider Provider = DefaultProvider>
[[nodiscard]]
auto sigma_initiator_begin_impl(const EcCurve curve)
    -> std::expected<SigmaInitiatorInitResult, CryptoError>
{
    auto eph = ecdh_generate_key_impl<Provider>(curve);
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

[[nodiscard]]
inline auto sigma_initiator_begin(const EcCurve curve)
    -> std::expected<SigmaInitiatorInitResult, CryptoError>
{
    return sigma_initiator_begin_impl(curve);
}


// Step 2 (Responder): receive Msg1, run ECDH, sign, MAC, produce Msg2 + session keys.
template<CryptoProvider Provider = DefaultProvider>
[[nodiscard]]
auto sigma_responder_respond_impl(  // NOLINT(readability-function-cognitive-complexity)
    const SigmaMsg1&  msg1,
    const EccKeyPair& responder_identity,
    const EcCurve     curve)
    -> std::expected<SigmaResponderRespondResult, CryptoError>
{
    // Generate responder ephemeral key pair.
    auto eph_r = ecdh_generate_key_impl<Provider>(curve);
    if (!eph_r.has_value()) {
        return std::unexpected(eph_r.error());
    }

    // ECDH with initiator's ephemeral public key.
    auto shared_secret = ecdh_compute_shared_secret_impl<Provider>(
        *eph_r, curve, msg1.ephemeral_pub_i);
    if (!shared_secret.has_value()) {
        return std::unexpected(shared_secret.error());
    }

    // Derive K_mac and K_session.
    auto keys = sigma_derive_keys_impl<Provider>(*shared_secret);
    if (!keys.has_value()) {
        return std::unexpected(keys.error());
    }

    // Sign eph_pub_i ‖ eph_pub_r with responder long-term identity key.
    const auto sign_input = detail::concat_buffers(msg1.ephemeral_pub_i, eph_r->public_key_der);
    auto sig_r = ecdsa_sign_impl<Provider>(responder_identity, curve, sign_input);
    if (!sig_r.has_value()) {
        return std::unexpected(sig_r.error());
    }

    // MAC over responder's long-term public key using K_mac.
    auto mac_r = hmac_generate_impl<ShaVariant::Sha384, Provider>(
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

[[nodiscard]]
inline auto sigma_responder_respond(
    const SigmaMsg1&  msg1,
    const EccKeyPair& responder_identity,
    const EcCurve     curve)
    -> std::expected<SigmaResponderRespondResult, CryptoError>
{
    return sigma_responder_respond_impl(msg1, responder_identity, curve);
}


// Step 3 (Initiator): verify Msg2, sign, MAC, produce Msg3 + session keys.
template<CryptoProvider Provider = DefaultProvider>
[[nodiscard]]
auto sigma_initiator_finish_impl(  // NOLINT(readability-function-cognitive-complexity)
    SigmaInitiatorState        state,
    const SigmaMsg2&           msg2,
    const EccKeyPair&          initiator_identity,
    const SecureBuffer&        expected_responder_pub,
    const EcCurve              curve)
    -> std::expected<SigmaInitiatorFinishResult, CryptoError>
{
    // ECDH with responder's ephemeral public key.
    auto shared_secret = ecdh_compute_shared_secret_impl<Provider>(
        state.ephemeral_key_pair, curve, msg2.ephemeral_pub_r);
    if (!shared_secret.has_value()) {
        // A key-agreement failure (invalid/tampered point) is an auth failure.
        // Other errors (init, import) propagate as-is.
        if (shared_secret.error().code() == CryptoErrorCode::KeyAgreementFailed) {
            return std::unexpected(CryptoError(
                CryptoErrorCode::SigmaAuthFailed,
                "Responder ephemeral key agreement failed"));
        }
        return std::unexpected(shared_secret.error());
    }

    auto keys = sigma_derive_keys_impl<Provider>(*shared_secret);
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
    auto mac_ok = hmac_verify_impl<ShaVariant::Sha384, Provider>(
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
    const auto sign_input = detail::concat_buffers(state.ephemeral_pub_i, msg2.ephemeral_pub_r);

    SecureBuffer responder_pub_copy(msg2.identity_pub_r.size());
    std::ranges::copy(msg2.identity_pub_r, responder_pub_copy.begin());
    const EcPublicKey responder_pub_only{ .public_key_der = std::move(responder_pub_copy) };

    auto sig_ok = ecdsa_verify_impl<Provider>(responder_pub_only, curve, sign_input, msg2.signature_r);
    if (!sig_ok.has_value()) {
        return std::unexpected(sig_ok.error());
    }
    if (!*sig_ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::SigmaAuthFailed,
            "Responder signature verification failed"));
    }

    // Sign eph_pub_i ‖ eph_pub_r with initiator long-term identity key.
    auto sig_i = ecdsa_sign_impl<Provider>(initiator_identity, curve, sign_input);
    if (!sig_i.has_value()) {
        return std::unexpected(sig_i.error());
    }

    // MAC over initiator's long-term public key using K_mac.
    auto mac_i = hmac_generate_impl<ShaVariant::Sha384, Provider>(
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

[[nodiscard]]
inline auto sigma_initiator_finish(
    SigmaInitiatorState        state,
    const SigmaMsg2&           msg2,
    const EccKeyPair&          initiator_identity,
    const SecureBuffer&        expected_responder_pub,
    const EcCurve              curve)
    -> std::expected<SigmaInitiatorFinishResult, CryptoError>
{
    return sigma_initiator_finish_impl(
        std::move(state), msg2, initiator_identity, expected_responder_pub, curve);
}


// Step 4 (Responder): verify Msg3. Returns false on auth failure, error on fault.
template<CryptoProvider Provider = DefaultProvider>
[[nodiscard]]
auto sigma_responder_finish_impl(  // NOLINT(readability-function-cognitive-complexity)
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
    auto mac_ok = hmac_verify_impl<ShaVariant::Sha384, Provider>(
        session_keys.mac_key, msg3.identity_pub_i, msg3.mac_i);
    if (!mac_ok.has_value()) {
        return std::unexpected(mac_ok.error());
    }
    if (!*mac_ok) {
        return false;
    }

    // Verify initiator signature over eph_pub_i ‖ eph_pub_r.
    const auto sign_input = detail::concat_buffers(msg1.ephemeral_pub_i, msg2.ephemeral_pub_r);

    SecureBuffer initiator_pub_copy(msg3.identity_pub_i.size());
    std::ranges::copy(msg3.identity_pub_i, initiator_pub_copy.begin());
    const EcPublicKey initiator_pub_only{ .public_key_der = std::move(initiator_pub_copy) };

    auto sig_ok = ecdsa_verify_impl<Provider>(initiator_pub_only, curve, sign_input, msg3.signature_i);
    if (!sig_ok.has_value()) {
        return std::unexpected(sig_ok.error());
    }

    return *sig_ok;
}

[[nodiscard]]
inline auto sigma_responder_finish(
    const SigmaMsg3&         msg3,
    const SigmaSessionKeys&  session_keys,
    const SigmaMsg1&         msg1,
    const SigmaMsg2&         msg2,
    const SecureBuffer&      expected_initiator_pub,
    const EcCurve            curve)
    -> std::expected<bool, CryptoError>
{
    return sigma_responder_finish_impl(
        msg3, session_keys, msg1, msg2, expected_initiator_pub, curve);
}
