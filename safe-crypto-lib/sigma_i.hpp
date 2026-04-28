/*
Copyright Permanence AI, 2026. All rights reserved.

*/

#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <expected>

#include "aead.hpp"
#include "contracts.hpp"
#include "crypto_error.hpp"
#include "defs.hpp"
#include "ecc.hpp"
#include "ecdh.hpp"
#include "mac.hpp"
#include "psa_backend.hpp"
#include "random.hpp"
#include "secure_buffer.hpp"
#include "sigma.hpp"


// Each party's identity bundle is AES-256-GCM encrypted in SIGMA-I.
constexpr std::size_t sigma_i_enc_key_size_bytes = 32;


// Encrypted identity bundle carried in Msg2 and Msg3.
// Plaintext is: [uint16_be: id_pub_len][id_pub][uint16_be: sig_len][sig][48-byte mac]
struct SigmaIBundle {
    FixedSecureBuffer<aes_gcm_iv_size_bytes> iv;
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


namespace detail {

struct SigmaIKeys {
    SecureBuffer mac_key;      // 48 bytes — HMAC-SHA-384
    SecureBuffer session_key;  // 32 bytes — application session key
    SecureBuffer enc_key_r;    // 32 bytes — AES-256 key for responder's Msg2 bundle
    SecureBuffer enc_key_i;    // 32 bytes — AES-256 key for initiator's Msg3 bundle
};


// Derives all four SIGMA-I keys from the raw ECDH shared secret via a single
// HKDF(SHA-384) operation.  Using full HKDF allows P-256's 32-byte shared
// secret to be used as IKM safely.
template<CryptoProvider Provider = RealPsaBackend>
[[nodiscard]]
auto sigma_i_derive_keys_impl(  // NOLINT(readability-function-cognitive-complexity)
    const SecureBuffer& shared_secret)
    -> std::expected<SigmaIKeys, CryptoError>
{
    constexpr std::size_t total_output =
        sigma_mac_key_size_bytes +
        sigma_session_key_size_bytes +
        sigma_i_enc_key_size_bytes +
        sigma_i_enc_key_size_bytes;

    constexpr std::array<CryptoByte, 7> info = {'s','i','g','m','a','-','i'};

    if (Provider::crypto_init() != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InitFailed,
            "PSA crypto init failed"));
    }

    auto attrs = Provider::make_hkdf_derive_attrs(shared_secret.size() * bits_per_byte);

    auto raw_key_id = Provider::null_key_id();
    if (Provider::import_key(&attrs,
                        shared_secret.data(), shared_secret.size(),
                        &raw_key_id) != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyImportFailed,
            "SIGMA-I IKM import failed"));
    }
    const PsaKeyHandle<Provider> key_handle(raw_key_id);

    auto op = Provider::make_kdf_op();

    if (Provider::key_derivation_setup(&op, Provider::alg_hkdf()) != Provider::ok) {
        Provider::key_derivation_abort(&op);
        return std::unexpected(CryptoError(
            CryptoErrorCode::KdfSetupFailed,
            "SIGMA-I HKDF setup failed"));
    }

    if (Provider::key_derivation_input_key(
            &op, Provider::kdf_step_secret(), key_handle.get()) != Provider::ok) {
        Provider::key_derivation_abort(&op);
        return std::unexpected(CryptoError(
            CryptoErrorCode::KdfInputFailed,
            "SIGMA-I HKDF secret input failed"));
    }

    if (Provider::key_derivation_input_bytes(
            &op, Provider::kdf_step_info(),
            info.data(), info.size()) != Provider::ok) {
        Provider::key_derivation_abort(&op);
        return std::unexpected(CryptoError(
            CryptoErrorCode::KdfInputFailed,
            "SIGMA-I HKDF info input failed"));
    }

    SecureBuffer output(total_output);
    if (Provider::key_derivation_output_bytes(
            &op, output.data(), output.size()) != Provider::ok) {
        Provider::key_derivation_abort(&op);
        return std::unexpected(CryptoError(
            CryptoErrorCode::KdfOutputFailed,
            "SIGMA-I HKDF output failed"));
    }

    Provider::key_derivation_abort(&op);

    auto slice = [&](const std::size_t offset, const std::size_t len) {
        SecureBuffer s(len);
        std::ranges::copy_n(
            output.begin() + static_cast<std::ptrdiff_t>(offset),
            static_cast<std::ptrdiff_t>(len),
            s.begin());
        return s;
    };

    constexpr std::size_t off_session = sigma_mac_key_size_bytes;
    constexpr std::size_t off_enc_r   = off_session + sigma_session_key_size_bytes;
    constexpr std::size_t off_enc_i   = off_enc_r   + sigma_i_enc_key_size_bytes;

    return SigmaIKeys{
        .mac_key      = slice(0,           sigma_mac_key_size_bytes),
        .session_key  = slice(off_session, sigma_session_key_size_bytes),
        .enc_key_r    = slice(off_enc_r,   sigma_i_enc_key_size_bytes),
        .enc_key_i    = slice(off_enc_i,   sigma_i_enc_key_size_bytes),
    };
}

[[nodiscard]]
inline auto sigma_i_derive_keys(const SecureBuffer& shared_secret)
    -> std::expected<SigmaIKeys, CryptoError>
{
    return sigma_i_derive_keys_impl(shared_secret);
}


// Serialises identity_pub ‖ signature ‖ mac into a single buffer with
// 2-byte big-endian length prefixes on the variable-length fields.
[[nodiscard]]
inline auto sigma_i_serialize_bundle(
    const SecureBuffer&                          identity_pub,
    const SecureBuffer&                          signature,
    const FixedSecureBuffer<sigma_mac_key_size_bytes>& mac)
    SAFE_CRYPTO_PRE(identity_pub.size() <= 65535)
    SAFE_CRYPTO_PRE(signature.size() <= 65535)
    -> SecureBuffer
{
    const std::size_t total =
        2 + identity_pub.size() +
        2 + signature.size() +
        sigma_mac_key_size_bytes;

    constexpr std::size_t  byte_shift = 8U;
    constexpr CryptoByte  byte_mask  = 0xFFU;

    SecureBuffer out(total);
    std::size_t  off = 0;

    const auto pub_len = static_cast<uint16_t>(identity_pub.size());
    // NOLINTBEGIN(cppcoreguidelines-pro-bounds-avoid-unchecked-container-access)
    out[off++] = static_cast<CryptoByte>(pub_len >> byte_shift);
    out[off++] = static_cast<CryptoByte>(pub_len & byte_mask);
    // NOLINTEND(cppcoreguidelines-pro-bounds-avoid-unchecked-container-access)
    std::ranges::copy(identity_pub, out.begin() + static_cast<std::ptrdiff_t>(off));
    off += identity_pub.size();

    const auto sig_len = static_cast<uint16_t>(signature.size());
    // NOLINTBEGIN(cppcoreguidelines-pro-bounds-avoid-unchecked-container-access)
    out[off++] = static_cast<CryptoByte>(sig_len >> byte_shift);
    out[off++] = static_cast<CryptoByte>(sig_len & byte_mask);
    // NOLINTEND(cppcoreguidelines-pro-bounds-avoid-unchecked-container-access)
    std::ranges::copy(signature, out.begin() + static_cast<std::ptrdiff_t>(off));
    off += signature.size();

    std::ranges::copy(mac, out.begin() + static_cast<std::ptrdiff_t>(off));

    return out;
}


struct SigmaIBundlePlaintext {
    SecureBuffer                              identity_pub;
    SecureBuffer                              signature;
    FixedSecureBuffer<sigma_mac_key_size_bytes> mac;
};


// Parses a serialised bundle.  Returns SigmaAuthFailed on malformed input so
// the caller doesn't need to distinguish parse errors from auth errors.
[[nodiscard]]
inline auto sigma_i_deserialize_bundle(const SecureBuffer& plaintext)
    -> std::expected<SigmaIBundlePlaintext, CryptoError>
{
    constexpr std::size_t min_size = 2 + 1 + 2 + 1 + sigma_mac_key_size_bytes;
    if (plaintext.size() < min_size) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::SigmaAuthFailed,
            "SIGMA-I bundle too short"));
    }

    std::size_t off = 0;

    constexpr std::size_t byte_shift = 8U;
    // NOLINTBEGIN(cppcoreguidelines-pro-bounds-avoid-unchecked-container-access)
    const std::size_t pub_len =
        (static_cast<std::size_t>(plaintext[off]) << byte_shift) |
         static_cast<std::size_t>(plaintext[off + 1]);
    // NOLINTEND(cppcoreguidelines-pro-bounds-avoid-unchecked-container-access)
    off += 2;

    if (off + pub_len + 2 + sigma_mac_key_size_bytes > plaintext.size()) {
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

    // NOLINTBEGIN(cppcoreguidelines-pro-bounds-avoid-unchecked-container-access)
    const std::size_t sig_len =
        (static_cast<std::size_t>(plaintext[off]) << byte_shift) |
         static_cast<std::size_t>(plaintext[off + 1]);
    // NOLINTEND(cppcoreguidelines-pro-bounds-avoid-unchecked-container-access)
    off += 2;

    if (off + sig_len + sigma_mac_key_size_bytes != plaintext.size()) {
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

    FixedSecureBuffer<sigma_mac_key_size_bytes> mac;
    std::ranges::copy_n(
        plaintext.begin() + static_cast<std::ptrdiff_t>(off),
        static_cast<std::ptrdiff_t>(sigma_mac_key_size_bytes),
        mac.begin());

    return SigmaIBundlePlaintext{
        .identity_pub = std::move(identity_pub),
        .signature    = std::move(signature),
        .mac          = std::move(mac),
    };
}


// AES-256-GCM encrypt using a SecureBuffer key (PSA direct — aes256_gcm_encrypt
// requires FixedSecureBuffer<32> which can't be constructed from a SecureBuffer slice).
template<CryptoProvider Provider = RealPsaBackend>
[[nodiscard]]
auto sigma_i_aes_gcm_encrypt_impl(  // NOLINT(readability-function-cognitive-complexity)
    const SecureBuffer& key,
    const SecureBuffer& plaintext)
    -> std::expected<SigmaIBundle, CryptoError>
{
    if (Provider::crypto_init() != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InitFailed,
            "PSA crypto init failed"));
    }

    auto iv = random_bytes_fixed_impl<aes_gcm_iv_size_bytes, Provider>();
    if (!iv.has_value()) {
        return std::unexpected(iv.error());
    }

    auto attrs = Provider::make_aes256_gcm_encrypt_attrs();

    auto raw_key_id = Provider::null_key_id();
    if (Provider::import_key(&attrs, key.data(), key.size(), &raw_key_id) != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyImportFailed,
            "SIGMA-I AES key import failed"));
    }
    const PsaKeyHandle<Provider> key_handle(raw_key_id);

    SecureBuffer ciphertext(Provider::aes_gcm_encrypt_output_size(plaintext.size()));

    std::size_t ciphertext_length = 0;
    const auto status = Provider::aead_encrypt(
        key_handle.get(), Provider::alg_aes_gcm(),
        iv->data(), iv->size(),
        nullptr, 0,
        plaintext.data(), plaintext.size(),
        ciphertext.data(), ciphertext.size(),
        &ciphertext_length);

    if (status != Provider::ok) {
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
inline auto sigma_i_aes_gcm_encrypt(
    const SecureBuffer& key,
    const SecureBuffer& plaintext)
    -> std::expected<SigmaIBundle, CryptoError>
{
    return sigma_i_aes_gcm_encrypt_impl(key, plaintext);
}


template<CryptoProvider Provider = RealPsaBackend>
[[nodiscard]]
auto sigma_i_aes_gcm_decrypt_impl(  // NOLINT(readability-function-cognitive-complexity)
    const SecureBuffer& key,
    const SigmaIBundle& bundle)
    -> std::expected<SecureBuffer, CryptoError>
{
    if (Provider::crypto_init() != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::InitFailed,
            "PSA crypto init failed"));
    }

    auto attrs = Provider::make_aes256_gcm_decrypt_attrs();

    auto raw_key_id = Provider::null_key_id();
    if (Provider::import_key(&attrs, key.data(), key.size(), &raw_key_id) != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::KeyImportFailed,
            "SIGMA-I AES key import failed"));
    }
    const PsaKeyHandle<Provider> key_handle(raw_key_id);

    SecureBuffer plaintext(Provider::aes_gcm_decrypt_output_size(bundle.ciphertext.size()));

    std::size_t plaintext_length = 0;
    const auto status = Provider::aead_decrypt(
        key_handle.get(), Provider::alg_aes_gcm(),
        bundle.iv.data(), bundle.iv.size(),
        nullptr, 0,
        bundle.ciphertext.data(), bundle.ciphertext.size(),
        plaintext.data(), plaintext.size(),
        &plaintext_length);

    if (status != Provider::ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::SigmaAuthFailed,
            "SIGMA-I bundle decryption failed"));
    }

    plaintext.resize(plaintext_length);
    return plaintext;
}

[[nodiscard]]
inline auto sigma_i_aes_gcm_decrypt(
    const SecureBuffer& key,
    const SigmaIBundle& bundle)
    -> std::expected<SecureBuffer, CryptoError>
{
    return sigma_i_aes_gcm_decrypt_impl(key, bundle);
}

}  // namespace detail


// Step 2 (Responder): receive Msg1, run ECDH, derive keys, encrypt identity bundle.
template<CryptoProvider Provider = RealPsaBackend>
[[nodiscard]]
auto sigma_i_responder_respond_impl(  // NOLINT(readability-function-cognitive-complexity)
    const SigmaMsg1&  msg1,
    const EccKeyPair& responder_identity,
    const EcCurve     curve)
    -> std::expected<SigmaIResponderRespondResult, CryptoError>
{
    auto eph_r = ecdh_generate_key_impl<Provider>(curve);
    if (!eph_r.has_value()) {
        return std::unexpected(eph_r.error());
    }

    auto shared_secret = ecdh_compute_shared_secret_impl<Provider>(
        *eph_r, curve, msg1.ephemeral_pub_i);
    if (!shared_secret.has_value()) {
        return std::unexpected(shared_secret.error());
    }

    auto keys = detail::sigma_i_derive_keys_impl<Provider>(*shared_secret);
    if (!keys.has_value()) {
        return std::unexpected(keys.error());
    }

    // Sign eph_pub_i ‖ eph_pub_r.
    const auto sign_input = detail::concat_buffers(msg1.ephemeral_pub_i, eph_r->public_key_der);
    auto sig_r = ecdsa_sign_impl<Provider>(responder_identity, curve, sign_input);
    if (!sig_r.has_value()) {
        return std::unexpected(sig_r.error());
    }

    // MAC over responder identity.
    auto mac_r = hmac_generate_impl<ShaVariant::Sha384, Provider>(
        keys->mac_key, responder_identity.public_key_der);
    if (!mac_r.has_value()) {
        return std::unexpected(mac_r.error());
    }

    // Encrypt the identity bundle.
    const auto plaintext_r = detail::sigma_i_serialize_bundle(
        responder_identity.public_key_der, *sig_r, *mac_r);
    auto bundle_r = detail::sigma_i_aes_gcm_encrypt_impl<Provider>(keys->enc_key_r, plaintext_r);
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

[[nodiscard]]
inline auto sigma_i_responder_respond(
    const SigmaMsg1&  msg1,
    const EccKeyPair& responder_identity,
    const EcCurve     curve)
    -> std::expected<SigmaIResponderRespondResult, CryptoError>
{
    return sigma_i_responder_respond_impl(msg1, responder_identity, curve);
}


// Step 3 (Initiator): decrypt and verify Msg2, encrypt own identity bundle.
template<CryptoProvider Provider = RealPsaBackend>
[[nodiscard]]
auto sigma_i_initiator_finish_impl(  // NOLINT(readability-function-cognitive-complexity)
    SigmaInitiatorState        state,
    const SigmaIMsg2&          msg2,
    const EccKeyPair&          initiator_identity,
    const SecureBuffer&        expected_responder_pub,
    const EcCurve              curve)
    -> std::expected<SigmaIInitiatorFinishResult, CryptoError>
{
    auto shared_secret = ecdh_compute_shared_secret_impl<Provider>(
        state.ephemeral_key_pair, curve, msg2.ephemeral_pub_r);
    if (!shared_secret.has_value()) {
        return std::unexpected(shared_secret.error());
    }

    auto keys = detail::sigma_i_derive_keys_impl<Provider>(*shared_secret);
    if (!keys.has_value()) {
        return std::unexpected(keys.error());
    }

    // Decrypt the responder bundle.
    auto plaintext_r = detail::sigma_i_aes_gcm_decrypt_impl<Provider>(keys->enc_key_r, msg2.bundle_r);
    if (!plaintext_r.has_value()) {
        return std::unexpected(plaintext_r.error());
    }

    auto bundle_r = detail::sigma_i_deserialize_bundle(*plaintext_r);
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
    auto mac_ok = hmac_verify_impl<ShaVariant::Sha384, Provider>(
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
    const auto sign_input = detail::concat_buffers(state.ephemeral_pub_i, msg2.ephemeral_pub_r);
    SecureBuffer responder_pub_copy(bundle_r->identity_pub.size());
    std::ranges::copy(bundle_r->identity_pub, responder_pub_copy.begin());
    const EcPublicKey responder_pub_only{ .public_key_der = std::move(responder_pub_copy) };
    auto sig_ok = ecdsa_verify_impl<Provider>(responder_pub_only, curve, sign_input, bundle_r->signature);
    if (!sig_ok.has_value()) {
        return std::unexpected(sig_ok.error());
    }
    if (!*sig_ok) {
        return std::unexpected(CryptoError(
            CryptoErrorCode::SigmaAuthFailed,
            "Responder signature verification failed"));
    }

    // Sign and MAC for the initiator bundle.
    auto sig_i = ecdsa_sign_impl<Provider>(initiator_identity, curve, sign_input);
    if (!sig_i.has_value()) {
        return std::unexpected(sig_i.error());
    }

    auto mac_i = hmac_generate_impl<ShaVariant::Sha384, Provider>(
        keys->mac_key, initiator_identity.public_key_der);
    if (!mac_i.has_value()) {
        return std::unexpected(mac_i.error());
    }

    // Encrypt the initiator bundle with K_enc_i.
    const auto plaintext_i = detail::sigma_i_serialize_bundle(
        initiator_identity.public_key_der, *sig_i, *mac_i);
    auto bundle_i = detail::sigma_i_aes_gcm_encrypt_impl<Provider>(keys->enc_key_i, plaintext_i);
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

[[nodiscard]]
inline auto sigma_i_initiator_finish(
    SigmaInitiatorState        state,
    const SigmaIMsg2&          msg2,
    const EccKeyPair&          initiator_identity,
    const SecureBuffer&        expected_responder_pub,
    const EcCurve              curve)
    -> std::expected<SigmaIInitiatorFinishResult, CryptoError>
{
    return sigma_i_initiator_finish_impl(
        std::move(state), msg2, initiator_identity, expected_responder_pub, curve);
}


// Step 4 (Responder): decrypt and verify Msg3.
template<CryptoProvider Provider = RealPsaBackend>
[[nodiscard]]
auto sigma_i_responder_finish_impl(  // NOLINT(readability-function-cognitive-complexity)
    const SigmaIMsg3&           msg3,
    const SigmaIResponderState& responder_state,
    const SigmaMsg1&            msg1,
    const SigmaIMsg2&           msg2,
    const SecureBuffer&         expected_initiator_pub,
    const EcCurve               curve)
    -> std::expected<bool, CryptoError>
{
    // Decrypt the initiator bundle with K_enc_i.
    auto plaintext_i = detail::sigma_i_aes_gcm_decrypt_impl<Provider>(responder_state.enc_key_i, msg3.bundle_i);
    if (!plaintext_i.has_value()) {
        return false;
    }

    auto bundle_i = detail::sigma_i_deserialize_bundle(*plaintext_i);
    if (!bundle_i.has_value()) {
        return false;
    }

    // Verify initiator identity.
    if (bundle_i->identity_pub.size() != expected_initiator_pub.size() ||
        !std::ranges::equal(bundle_i->identity_pub, expected_initiator_pub)) {
        return false;
    }

    // Verify HMAC.
    auto mac_ok = hmac_verify_impl<ShaVariant::Sha384, Provider>(
        responder_state.session_keys.mac_key, bundle_i->identity_pub, bundle_i->mac);
    if (!mac_ok.has_value()) {
        return std::unexpected(mac_ok.error());
    }
    if (!*mac_ok) {
        return false;
    }

    // Verify initiator signature.
    const auto sign_input = detail::concat_buffers(msg1.ephemeral_pub_i, msg2.ephemeral_pub_r);
    SecureBuffer initiator_pub_copy(bundle_i->identity_pub.size());
    std::ranges::copy(bundle_i->identity_pub, initiator_pub_copy.begin());
    const EcPublicKey initiator_pub_only{ .public_key_der = std::move(initiator_pub_copy) };
    auto sig_ok = ecdsa_verify_impl<Provider>(initiator_pub_only, curve, sign_input, bundle_i->signature);
    if (!sig_ok.has_value()) {
        return std::unexpected(sig_ok.error());
    }

    return *sig_ok;
}

[[nodiscard]]
inline auto sigma_i_responder_finish(
    const SigmaIMsg3&           msg3,
    const SigmaIResponderState& responder_state,
    const SigmaMsg1&            msg1,
    const SigmaIMsg2&           msg2,
    const SecureBuffer&         expected_initiator_pub,
    const EcCurve               curve)
    -> std::expected<bool, CryptoError>
{
    return sigma_i_responder_finish_impl(
        msg3, responder_state, msg1, msg2, expected_initiator_pub, curve);
}
