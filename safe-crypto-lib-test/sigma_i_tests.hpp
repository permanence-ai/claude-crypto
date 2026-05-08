// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <algorithm>
#include <cstddef>
#include <span>

#include <gtest/gtest.h>

#include "ecc.hpp"
#include "sigma_i.hpp"
#include "test_utils.hpp"


class SigmaITests : public ::testing::Test {
};


struct SigmaIHandshakeResult {
    SigmaSessionKeys initiator_keys;
    SigmaSessionKeys responder_keys;
};

[[nodiscard]]
static auto run_sigma_i_handshake(
    const EccKeyPair& initiator_identity,
    const EccKeyPair& responder_identity,
    const EcCurve     curve)
    -> SigmaIHandshakeResult
{
    // Step 1
    auto init_result = sigma_initiator_begin(curve);
    EXPECT_TRUE(init_result.has_value());

    // Step 2
    auto resp_result = sigma_i_responder_respond(
        init_result->msg1, responder_identity, curve);
    EXPECT_TRUE(resp_result.has_value());

    // Step 3
    SecureBuffer expected_resp_pub(responder_identity.public_key_der.size());
    std::ranges::copy(responder_identity.public_key_der, expected_resp_pub.begin());

    auto finish_result = sigma_i_initiator_finish(
        std::move(init_result->state),
        resp_result->msg2,
        initiator_identity,
        expected_resp_pub,
        curve);
    EXPECT_TRUE(finish_result.has_value());

    // Step 4
    SecureBuffer expected_init_pub(initiator_identity.public_key_der.size());
    std::ranges::copy(initiator_identity.public_key_der, expected_init_pub.begin());

    auto verify_result = sigma_i_responder_finish(
        finish_result->msg3,
        resp_result->responder_state,
        init_result->msg1,
        resp_result->msg2,
        expected_init_pub,
        curve);
    EXPECT_TRUE(verify_result.has_value());
    EXPECT_TRUE(*verify_result);

    return SigmaIHandshakeResult{
        .initiator_keys = std::move(finish_result->session_keys),
        .responder_keys = std::move(resp_result->responder_state.session_keys),
    };
}


TEST_F(SigmaITests, P256HandshakeSucceeds) {
    const auto initiator = ecdsa_generate_key(EcCurve::P256);
    const auto responder = ecdsa_generate_key(EcCurve::P256);
    ASSERT_TRUE(initiator.has_value());
    ASSERT_TRUE(responder.has_value());

    const auto result = run_sigma_i_handshake(*initiator, *responder, EcCurve::P256);

    EXPECT_FALSE(result.initiator_keys.session_key.empty());
    EXPECT_FALSE(result.responder_keys.session_key.empty());
}


TEST_F(SigmaITests, P384HandshakeSucceeds) {
    const auto initiator = ecdsa_generate_key(EcCurve::P384);
    const auto responder = ecdsa_generate_key(EcCurve::P384);
    ASSERT_TRUE(initiator.has_value());
    ASSERT_TRUE(responder.has_value());

    const auto result = run_sigma_i_handshake(*initiator, *responder, EcCurve::P384);

    EXPECT_FALSE(result.initiator_keys.session_key.empty());
    EXPECT_FALSE(result.responder_keys.session_key.empty());
}


TEST_F(SigmaITests, P521HandshakeSucceeds) {
    const auto initiator = ecdsa_generate_key(EcCurve::P521);
    const auto responder = ecdsa_generate_key(EcCurve::P521);
    ASSERT_TRUE(initiator.has_value());
    ASSERT_TRUE(responder.has_value());

    const auto result = run_sigma_i_handshake(*initiator, *responder, EcCurve::P521);

    EXPECT_FALSE(result.initiator_keys.session_key.empty());
    EXPECT_FALSE(result.responder_keys.session_key.empty());
}


TEST_F(SigmaITests, BothSidesDeriveIdenticalSessionKeys) {
    const auto initiator = ecdsa_generate_key(EcCurve::P256);
    const auto responder = ecdsa_generate_key(EcCurve::P256);
    ASSERT_TRUE(initiator.has_value());
    ASSERT_TRUE(responder.has_value());

    const auto result = run_sigma_i_handshake(*initiator, *responder, EcCurve::P256);

    ASSERT_EQ(result.initiator_keys.session_key.size(),
              result.responder_keys.session_key.size());
    EXPECT_TRUE(std::ranges::equal(
        std::span(result.initiator_keys.session_key.data(),
                  result.initiator_keys.session_key.size()),
        std::span(result.responder_keys.session_key.data(),
                  result.responder_keys.session_key.size())));
}


// NOLINTNEXTLINE(readability-function-cognitive-complexity)
TEST_F(SigmaITests, IdentitiesAreNotExposedInMsg2) {
    const auto initiator = ecdsa_generate_key(EcCurve::P256);
    const auto responder = ecdsa_generate_key(EcCurve::P256);
    ASSERT_TRUE(initiator.has_value());
    ASSERT_TRUE(responder.has_value());

    auto init_result = sigma_initiator_begin(EcCurve::P256);
    ASSERT_TRUE(init_result.has_value());

    auto resp_result = sigma_i_responder_respond(
        init_result->msg1, *responder, EcCurve::P256);
    ASSERT_TRUE(resp_result.has_value());

    // The responder's raw public key bytes must not appear verbatim in the bundle ciphertext.
    const auto& pub = responder->public_key_der;
    const auto& ct  = resp_result->msg2.bundle_r.ciphertext;
    ASSERT_GE(ct.size(), pub.size());
    bool found = false;
    for (std::size_t i = 0; i + pub.size() <= ct.size(); ++i) {
        if (std::ranges::equal(
                // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
                std::span(ct.data() + i, pub.size()),
                std::span(pub.data(), pub.size()))) {
            found = true;
            break;
        }
    }
    EXPECT_FALSE(found);
}


TEST_F(SigmaITests, InitiatorRejectsWrongResponderIdentity) {
    const auto initiator  = ecdsa_generate_key(EcCurve::P256);
    const auto responder  = ecdsa_generate_key(EcCurve::P256);
    const auto wrong_resp = ecdsa_generate_key(EcCurve::P256);
    ASSERT_TRUE(initiator.has_value());
    ASSERT_TRUE(responder.has_value());
    ASSERT_TRUE(wrong_resp.has_value());

    auto init_result = sigma_initiator_begin(EcCurve::P256);
    ASSERT_TRUE(init_result.has_value());

    auto resp_result = sigma_i_responder_respond(
        init_result->msg1, *responder, EcCurve::P256);
    ASSERT_TRUE(resp_result.has_value());

    SecureBuffer wrong_pub(wrong_resp->public_key_der.size());
    std::ranges::copy(wrong_resp->public_key_der, wrong_pub.begin());

    const auto finish = sigma_i_initiator_finish(
        std::move(init_result->state),
        resp_result->msg2,
        *initiator,
        wrong_pub,
        EcCurve::P256);

    ASSERT_FALSE(finish.has_value());
    EXPECT_EQ(finish.error().code(), CryptoErrorCode::SigmaAuthFailed);
}


TEST_F(SigmaITests, InitiatorRejectsTamperedBundle) {
    constexpr CryptoByte TAMPER_BYTE = 0xFF;

    const auto initiator = ecdsa_generate_key(EcCurve::P256);
    const auto responder = ecdsa_generate_key(EcCurve::P256);
    ASSERT_TRUE(initiator.has_value());
    ASSERT_TRUE(responder.has_value());

    auto init_result = sigma_initiator_begin(EcCurve::P256);
    ASSERT_TRUE(init_result.has_value());

    auto resp_result = sigma_i_responder_respond(
        init_result->msg1, *responder, EcCurve::P256);
    ASSERT_TRUE(resp_result.has_value());

    resp_result->msg2.bundle_r.ciphertext[0] ^= TAMPER_BYTE;  // NOLINT(cppcoreguidelines-pro-bounds-avoid-unchecked-container-access)

    SecureBuffer expected_pub(responder->public_key_der.size());
    std::ranges::copy(responder->public_key_der, expected_pub.begin());

    const auto finish = sigma_i_initiator_finish(
        std::move(init_result->state),
        resp_result->msg2,
        *initiator,
        expected_pub,
        EcCurve::P256);

    ASSERT_FALSE(finish.has_value());
    EXPECT_EQ(finish.error().code(), CryptoErrorCode::SigmaAuthFailed);
}


TEST_F(SigmaITests, ResponderRejectsWrongInitiatorIdentity) {
    const auto initiator  = ecdsa_generate_key(EcCurve::P256);
    const auto responder  = ecdsa_generate_key(EcCurve::P256);
    const auto wrong_init = ecdsa_generate_key(EcCurve::P256);
    ASSERT_TRUE(initiator.has_value());
    ASSERT_TRUE(responder.has_value());
    ASSERT_TRUE(wrong_init.has_value());

    auto init_result = sigma_initiator_begin(EcCurve::P256);
    ASSERT_TRUE(init_result.has_value());

    auto resp_result = sigma_i_responder_respond(
        init_result->msg1, *responder, EcCurve::P256);
    ASSERT_TRUE(resp_result.has_value());

    SecureBuffer expected_resp_pub(responder->public_key_der.size());
    std::ranges::copy(responder->public_key_der, expected_resp_pub.begin());

    auto finish_result = sigma_i_initiator_finish(
        std::move(init_result->state),
        resp_result->msg2,
        *initiator,
        expected_resp_pub,
        EcCurve::P256);
    ASSERT_TRUE(finish_result.has_value());

    SecureBuffer wrong_pub(wrong_init->public_key_der.size());
    std::ranges::copy(wrong_init->public_key_der, wrong_pub.begin());

    const auto verify = sigma_i_responder_finish(
        finish_result->msg3,
        resp_result->responder_state,
        init_result->msg1,
        resp_result->msg2,
        wrong_pub,
        EcCurve::P256);

    ASSERT_TRUE(verify.has_value());
    EXPECT_FALSE(*verify);
}


TEST_F(SigmaITests, ResponderRejectsTamperedBundle) {
    constexpr CryptoByte TAMPER_BYTE = 0xFF;

    const auto initiator = ecdsa_generate_key(EcCurve::P256);
    const auto responder = ecdsa_generate_key(EcCurve::P256);
    ASSERT_TRUE(initiator.has_value());
    ASSERT_TRUE(responder.has_value());

    auto init_result = sigma_initiator_begin(EcCurve::P256);
    ASSERT_TRUE(init_result.has_value());

    auto resp_result = sigma_i_responder_respond(
        init_result->msg1, *responder, EcCurve::P256);
    ASSERT_TRUE(resp_result.has_value());

    SecureBuffer expected_resp_pub(responder->public_key_der.size());
    std::ranges::copy(responder->public_key_der, expected_resp_pub.begin());

    auto finish_result = sigma_i_initiator_finish(
        std::move(init_result->state),
        resp_result->msg2,
        *initiator,
        expected_resp_pub,
        EcCurve::P256);
    ASSERT_TRUE(finish_result.has_value());

    finish_result->msg3.bundle_i.ciphertext[0] ^= TAMPER_BYTE;  // NOLINT(cppcoreguidelines-pro-bounds-avoid-unchecked-container-access)

    SecureBuffer expected_init_pub(initiator->public_key_der.size());
    std::ranges::copy(initiator->public_key_der, expected_init_pub.begin());

    const auto verify = sigma_i_responder_finish(
        finish_result->msg3,
        resp_result->responder_state,
        init_result->msg1,
        resp_result->msg2,
        expected_init_pub,
        EcCurve::P256);

    ASSERT_TRUE(verify.has_value());
    EXPECT_FALSE(*verify);
}


TEST_F(SigmaITests, InitiatorRejectsTamperedBundleIv) {
    constexpr CryptoByte TAMPER_BYTE = 0xFF;

    const auto initiator = ecdsa_generate_key(EcCurve::P256);
    const auto responder = ecdsa_generate_key(EcCurve::P256);
    ASSERT_TRUE(initiator.has_value());
    ASSERT_TRUE(responder.has_value());

    auto init_result = sigma_initiator_begin(EcCurve::P256);
    ASSERT_TRUE(init_result.has_value());

    auto resp_result = sigma_i_responder_respond(
        init_result->msg1, *responder, EcCurve::P256);
    ASSERT_TRUE(resp_result.has_value());

    // Corrupt the responder's bundle IV — AES-GCM auth tag will not match.
    resp_result->msg2.bundle_r.iv[0] ^= TAMPER_BYTE;  // NOLINT(cppcoreguidelines-pro-bounds-avoid-unchecked-container-access)

    SecureBuffer expected_pub(responder->public_key_der.size());
    std::ranges::copy(responder->public_key_der, expected_pub.begin());

    const auto finish = sigma_i_initiator_finish(
        std::move(init_result->state),
        resp_result->msg2,
        *initiator,
        expected_pub,
        EcCurve::P256);

    ASSERT_FALSE(finish.has_value());
    EXPECT_EQ(finish.error().code(), CryptoErrorCode::SigmaAuthFailed);
}


TEST_F(SigmaITests, ResponderRejectsTamperedBundleIv) {
    constexpr CryptoByte TAMPER_BYTE = 0xFF;

    const auto initiator = ecdsa_generate_key(EcCurve::P256);
    const auto responder = ecdsa_generate_key(EcCurve::P256);
    ASSERT_TRUE(initiator.has_value());
    ASSERT_TRUE(responder.has_value());

    auto init_result = sigma_initiator_begin(EcCurve::P256);
    ASSERT_TRUE(init_result.has_value());

    auto resp_result = sigma_i_responder_respond(
        init_result->msg1, *responder, EcCurve::P256);
    ASSERT_TRUE(resp_result.has_value());

    SecureBuffer expected_resp_pub(responder->public_key_der.size());
    std::ranges::copy(responder->public_key_der, expected_resp_pub.begin());

    auto finish_result = sigma_i_initiator_finish(
        std::move(init_result->state),
        resp_result->msg2,
        *initiator,
        expected_resp_pub,
        EcCurve::P256);
    ASSERT_TRUE(finish_result.has_value());

    // Corrupt the initiator's bundle IV — AES-GCM auth tag will not match.
    finish_result->msg3.bundle_i.iv[0] ^= TAMPER_BYTE;  // NOLINT(cppcoreguidelines-pro-bounds-avoid-unchecked-container-access)

    SecureBuffer expected_init_pub(initiator->public_key_der.size());
    std::ranges::copy(initiator->public_key_der, expected_init_pub.begin());

    const auto verify = sigma_i_responder_finish(
        finish_result->msg3,
        resp_result->responder_state,
        init_result->msg1,
        resp_result->msg2,
        expected_init_pub,
        EcCurve::P256);

    ASSERT_TRUE(verify.has_value());
    EXPECT_FALSE(*verify);
}


// -----------------------------------------------------------------------
// Tests for the non-template wrapper overloads (sigma_i_derive_keys,
// sigma_i_aes_gcm_encrypt, sigma_i_aes_gcm_decrypt).  The handshake tests
// above exercise only the *_impl<Provider> paths; these tests hit the
// default-provider wrappers that would otherwise be dead code.
// -----------------------------------------------------------------------

class SigmaIWrapperTests : public ::testing::Test {
};


TEST_F(SigmaIWrapperTests, DeriveKeysProducesExpectedSizes) {
    // Build a real shared secret via ECDH so the PSA key derivation path works.
    const auto key_a = ecdh_generate_key(EcCurve::P256);
    const auto key_b = ecdh_generate_key(EcCurve::P256);
    ASSERT_TRUE(key_a.has_value());
    ASSERT_TRUE(key_b.has_value());

    const auto secret = ecdh_compute_shared_secret(*key_a, EcCurve::P256, key_b->public_key_der);
    ASSERT_TRUE(secret.has_value());

    const auto keys = detail::sigma_i_derive_keys(*secret);
    ASSERT_TRUE(keys.has_value());

    EXPECT_EQ(keys->mac_key.size(),     sigma_mac_key_size_bytes);
    EXPECT_EQ(keys->session_key.size(), sigma_session_key_size_bytes);
    EXPECT_EQ(keys->enc_key_r.size(),   sigma_i_enc_key_size_bytes);
    EXPECT_EQ(keys->enc_key_i.size(),   sigma_i_enc_key_size_bytes);
}


TEST_F(SigmaIWrapperTests, AesGcmEncryptDecryptRoundTrip) {
    // Derive a real key via the wrapper.
    const auto key_a = ecdh_generate_key(EcCurve::P256);
    const auto key_b = ecdh_generate_key(EcCurve::P256);
    ASSERT_TRUE(key_a.has_value());
    ASSERT_TRUE(key_b.has_value());

    const auto secret = ecdh_compute_shared_secret(*key_a, EcCurve::P256, key_b->public_key_der);
    ASSERT_TRUE(secret.has_value());

    const auto keys = detail::sigma_i_derive_keys(*secret);
    ASSERT_TRUE(keys.has_value());

    // Plaintext to encrypt.
    SecureBuffer plaintext(16);
    for (std::size_t i = 0; i < 16; ++i) {
        plaintext[i] = static_cast<CryptoByte>(i + 1);  // NOLINT(cppcoreguidelines-pro-bounds-avoid-unchecked-container-access)
    }

    // Encrypt via wrapper.
    const auto bundle = detail::sigma_i_aes_gcm_encrypt(keys->enc_key_r, plaintext);
    ASSERT_TRUE(bundle.has_value());
    EXPECT_EQ(bundle->iv.size(), aes_gcm_iv_size_bytes);
    EXPECT_FALSE(bundle->ciphertext.empty());

    // Decrypt via wrapper.
    const auto recovered = detail::sigma_i_aes_gcm_decrypt(keys->enc_key_r, *bundle);
    ASSERT_TRUE(recovered.has_value());

    ASSERT_EQ(recovered->size(), plaintext.size());
    EXPECT_TRUE(std::ranges::equal(*recovered, plaintext));
}


// -----------------------------------------------------------------------
// Direct tests for sigma_i_deserialize_bundle parse-error paths.
// These branches are unreachable through the full handshake because
// AES-GCM tag verification intercepts ciphertext tampering before the
// deserializer ever sees the plaintext.
// -----------------------------------------------------------------------

class SigmaIDeserializeTests : public ::testing::Test {};

TEST_F(SigmaIDeserializeTests, BundleTooShortIsRejected) {
    // min_size = 2+1+2+1+48 = 54; pass 53 bytes.
    constexpr std::size_t min_size = 2 + 1 + 2 + 1 + sigma_mac_key_size_bytes;
    SecureBuffer buf(min_size - 1);
    std::ranges::fill(buf, CryptoByte{0});
    const auto result = detail::sigma_i_deserialize_bundle(buf);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::SigmaAuthFailed);
}

TEST_F(SigmaIDeserializeTests, PubLenTooLargeIsRejected) {
    // 54-byte buffer, pub_len=3: 2+3+2+48=55 > 54 → identity_pub length invalid.
    constexpr std::size_t min_size = 2 + 1 + 2 + 1 + sigma_mac_key_size_bytes;
    SecureBuffer buf(min_size);
    std::ranges::fill(buf, CryptoByte{0});
    // NOLINTBEGIN(cppcoreguidelines-pro-bounds-avoid-unchecked-container-access)
    buf[0] = 0x00;
    buf[1] = 0x03;  // pub_len = 3, too large for this buffer
    // NOLINTEND(cppcoreguidelines-pro-bounds-avoid-unchecked-container-access)
    const auto result = detail::sigma_i_deserialize_bundle(buf);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::SigmaAuthFailed);
}

TEST_F(SigmaIDeserializeTests, SigLenMismatchIsRejected) {
    // 54-byte buffer, pub_len=1, sig_len=2: 4+1+2+48=55 != 54 → sig length invalid.
    constexpr std::size_t min_size = 2 + 1 + 2 + 1 + sigma_mac_key_size_bytes;
    SecureBuffer buf(min_size);
    std::ranges::fill(buf, CryptoByte{0});
    // NOLINTBEGIN(cppcoreguidelines-pro-bounds-avoid-unchecked-container-access)
    buf[0] = 0x00;
    buf[1] = 0x01;  // pub_len = 1 (valid — fits in 54 bytes)
    // offset 2: identity_pub byte (0x00)
    buf[3] = 0x00;
    buf[4] = 0x02;  // sig_len = 2, but only 1 byte of sig fits before the 48-byte mac
    // NOLINTEND(cppcoreguidelines-pro-bounds-avoid-unchecked-container-access)
    const auto result = detail::sigma_i_deserialize_bundle(buf);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::SigmaAuthFailed);
}


TEST_F(SigmaIWrapperTests, AesGcmDecryptFailsWithWrongKey) {
    const auto key_a = ecdh_generate_key(EcCurve::P256);
    const auto key_b = ecdh_generate_key(EcCurve::P256);
    ASSERT_TRUE(key_a.has_value());
    ASSERT_TRUE(key_b.has_value());

    const auto secret = ecdh_compute_shared_secret(*key_a, EcCurve::P256, key_b->public_key_der);
    ASSERT_TRUE(secret.has_value());

    const auto keys = detail::sigma_i_derive_keys(*secret);
    ASSERT_TRUE(keys.has_value());

    SecureBuffer plaintext(16);
    std::ranges::fill(plaintext, static_cast<CryptoByte>(0xAB));

    const auto bundle = detail::sigma_i_aes_gcm_encrypt(keys->enc_key_r, plaintext);
    ASSERT_TRUE(bundle.has_value());

    // Decrypt with the wrong key (enc_key_i instead of enc_key_r).
    const auto result = detail::sigma_i_aes_gcm_decrypt(keys->enc_key_i, *bundle);
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::SigmaAuthFailed);
}
