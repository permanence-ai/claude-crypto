// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Permanence AI

#pragma once

#include <algorithm>
#include <cstddef>
#include <span>

#include <gtest/gtest.h>

#include "aead.hpp"
#include "ecc.hpp"
#include "sigma.hpp"
#include "test_utils.hpp"


class SigmaTests : public ::testing::Test {
};


// Helper: run a full 4-step handshake and return both session key pairs.
struct HandshakeResult {
    SigmaSessionKeys initiator_keys;
    SigmaSessionKeys responder_keys;
};

[[nodiscard]]
static auto run_handshake(
    const EccKeyPair& initiator_identity,
    const EccKeyPair& responder_identity,
    const EcCurve     curve)
    -> HandshakeResult
{
    auto init_result = sigma_initiator_begin(curve);
    EXPECT_TRUE(init_result.has_value());

    auto resp_result = sigma_responder_respond(
        init_result->msg1, responder_identity, curve);
    EXPECT_TRUE(resp_result.has_value());

    SecureBuffer expected_resp_pub(responder_identity.public_key_der.size());
    std::ranges::copy(responder_identity.public_key_der, expected_resp_pub.begin());

    auto finish_result = sigma_initiator_finish(
        std::move(init_result->state),
        resp_result->msg2,
        initiator_identity,
        expected_resp_pub,
        curve);
    EXPECT_TRUE(finish_result.has_value());

    SecureBuffer expected_init_pub(initiator_identity.public_key_der.size());
    std::ranges::copy(initiator_identity.public_key_der, expected_init_pub.begin());

    auto verify_result = sigma_responder_finish(
        finish_result->msg3,
        resp_result->session_keys,
        init_result->msg1,
        resp_result->msg2,
        expected_init_pub,
        curve);
    EXPECT_TRUE(verify_result.has_value());
    EXPECT_TRUE(*verify_result);

    return HandshakeResult{
        .initiator_keys = std::move(finish_result->session_keys),
        .responder_keys = std::move(resp_result->session_keys),
    };
}


TEST_F(SigmaTests, P256HandshakeSucceeds) {
    const auto initiator = ecdsa_generate_key(EcCurve::P256);
    const auto responder = ecdsa_generate_key(EcCurve::P256);
    ASSERT_TRUE(initiator.has_value());
    ASSERT_TRUE(responder.has_value());

    const auto result = run_handshake(*initiator, *responder, EcCurve::P256);

    EXPECT_FALSE(result.initiator_keys.session_key.empty());
    EXPECT_FALSE(result.responder_keys.session_key.empty());
}


TEST_F(SigmaTests, P384HandshakeSucceeds) {
    const auto initiator = ecdsa_generate_key(EcCurve::P384);
    const auto responder = ecdsa_generate_key(EcCurve::P384);
    ASSERT_TRUE(initiator.has_value());
    ASSERT_TRUE(responder.has_value());

    const auto result = run_handshake(*initiator, *responder, EcCurve::P384);

    EXPECT_FALSE(result.initiator_keys.session_key.empty());
    EXPECT_FALSE(result.responder_keys.session_key.empty());
}


TEST_F(SigmaTests, P521HandshakeSucceeds) {
    const auto initiator = ecdsa_generate_key(EcCurve::P521);
    const auto responder = ecdsa_generate_key(EcCurve::P521);
    ASSERT_TRUE(initiator.has_value());
    ASSERT_TRUE(responder.has_value());

    const auto result = run_handshake(*initiator, *responder, EcCurve::P521);

    EXPECT_FALSE(result.initiator_keys.session_key.empty());
    EXPECT_FALSE(result.responder_keys.session_key.empty());
}


TEST_F(SigmaTests, BothSidesDeriveIdenticalSessionKeys) {
    const auto initiator = ecdsa_generate_key(EcCurve::P256);
    const auto responder = ecdsa_generate_key(EcCurve::P256);
    ASSERT_TRUE(initiator.has_value());
    ASSERT_TRUE(responder.has_value());

    const auto result = run_handshake(*initiator, *responder, EcCurve::P256);

    ASSERT_EQ(result.initiator_keys.session_key.size(),
              result.responder_keys.session_key.size());
    EXPECT_TRUE(std::ranges::equal(
        std::span(result.initiator_keys.session_key.data(),
                  result.initiator_keys.session_key.size()),
        std::span(result.responder_keys.session_key.data(),
                  result.responder_keys.session_key.size())));

    ASSERT_EQ(result.initiator_keys.mac_key.size(),
              result.responder_keys.mac_key.size());
    EXPECT_TRUE(std::ranges::equal(
        std::span(result.initiator_keys.mac_key.data(),
                  result.initiator_keys.mac_key.size()),
        std::span(result.responder_keys.mac_key.data(),
                  result.responder_keys.mac_key.size())));
}


TEST_F(SigmaTests, InitiatorRejectsWrongResponderIdentity) {
    const auto initiator     = ecdsa_generate_key(EcCurve::P256);
    const auto responder     = ecdsa_generate_key(EcCurve::P256);
    const auto wrong_resp    = ecdsa_generate_key(EcCurve::P256);
    ASSERT_TRUE(initiator.has_value());
    ASSERT_TRUE(responder.has_value());
    ASSERT_TRUE(wrong_resp.has_value());

    auto init_result = sigma_initiator_begin(EcCurve::P256);
    ASSERT_TRUE(init_result.has_value());

    auto resp_result = sigma_responder_respond(
        init_result->msg1, *responder, EcCurve::P256);
    ASSERT_TRUE(resp_result.has_value());

    // Present the wrong public key as the expected responder.
    SecureBuffer wrong_pub(wrong_resp->public_key_der.size());
    std::ranges::copy(wrong_resp->public_key_der, wrong_pub.begin());

    const auto finish = sigma_initiator_finish(
        std::move(init_result->state),
        resp_result->msg2,
        *initiator,
        wrong_pub,
        EcCurve::P256);

    ASSERT_FALSE(finish.has_value());
    EXPECT_EQ(finish.error().code(), CryptoErrorCode::SigmaAuthFailed);
}


TEST_F(SigmaTests, InitiatorRejectsTamperedResponderMac) {
    constexpr CryptoByte TAMPER_BYTE = 0xFF;

    const auto initiator = ecdsa_generate_key(EcCurve::P256);
    const auto responder = ecdsa_generate_key(EcCurve::P256);
    ASSERT_TRUE(initiator.has_value());
    ASSERT_TRUE(responder.has_value());

    auto init_result = sigma_initiator_begin(EcCurve::P256);
    ASSERT_TRUE(init_result.has_value());

    auto resp_result = sigma_responder_respond(
        init_result->msg1, *responder, EcCurve::P256);
    ASSERT_TRUE(resp_result.has_value());

    resp_result->msg2.mac_r[0] ^= TAMPER_BYTE;  // NOLINT(cppcoreguidelines-pro-bounds-avoid-unchecked-container-access)

    SecureBuffer expected_pub(responder->public_key_der.size());
    std::ranges::copy(responder->public_key_der, expected_pub.begin());

    const auto finish = sigma_initiator_finish(
        std::move(init_result->state),
        resp_result->msg2,
        *initiator,
        expected_pub,
        EcCurve::P256);

    ASSERT_FALSE(finish.has_value());
    EXPECT_EQ(finish.error().code(), CryptoErrorCode::SigmaAuthFailed);
}


TEST_F(SigmaTests, InitiatorRejectsTamperedResponderSignature) {
    constexpr CryptoByte TAMPER_BYTE = 0xFF;

    const auto initiator = ecdsa_generate_key(EcCurve::P256);
    const auto responder = ecdsa_generate_key(EcCurve::P256);
    ASSERT_TRUE(initiator.has_value());
    ASSERT_TRUE(responder.has_value());

    auto init_result = sigma_initiator_begin(EcCurve::P256);
    ASSERT_TRUE(init_result.has_value());

    auto resp_result = sigma_responder_respond(
        init_result->msg1, *responder, EcCurve::P256);
    ASSERT_TRUE(resp_result.has_value());

    resp_result->msg2.signature_r[0] ^= TAMPER_BYTE;  // NOLINT(cppcoreguidelines-pro-bounds-avoid-unchecked-container-access)

    SecureBuffer expected_pub(responder->public_key_der.size());
    std::ranges::copy(responder->public_key_der, expected_pub.begin());

    const auto finish = sigma_initiator_finish(
        std::move(init_result->state),
        resp_result->msg2,
        *initiator,
        expected_pub,
        EcCurve::P256);

    ASSERT_FALSE(finish.has_value());
    EXPECT_EQ(finish.error().code(), CryptoErrorCode::SigmaAuthFailed);
}


TEST_F(SigmaTests, ResponderRejectsWrongInitiatorIdentity) {
    const auto initiator  = ecdsa_generate_key(EcCurve::P256);
    const auto responder  = ecdsa_generate_key(EcCurve::P256);
    const auto wrong_init = ecdsa_generate_key(EcCurve::P256);
    ASSERT_TRUE(initiator.has_value());
    ASSERT_TRUE(responder.has_value());
    ASSERT_TRUE(wrong_init.has_value());

    auto init_result = sigma_initiator_begin(EcCurve::P256);
    ASSERT_TRUE(init_result.has_value());

    auto resp_result = sigma_responder_respond(
        init_result->msg1, *responder, EcCurve::P256);
    ASSERT_TRUE(resp_result.has_value());

    SecureBuffer expected_resp_pub(responder->public_key_der.size());
    std::ranges::copy(responder->public_key_der, expected_resp_pub.begin());

    auto finish_result = sigma_initiator_finish(
        std::move(init_result->state),
        resp_result->msg2,
        *initiator,
        expected_resp_pub,
        EcCurve::P256);
    ASSERT_TRUE(finish_result.has_value());

    // Supply a different identity as the expected initiator.
    SecureBuffer wrong_pub(wrong_init->public_key_der.size());
    std::ranges::copy(wrong_init->public_key_der, wrong_pub.begin());

    const auto verify = sigma_responder_finish(
        finish_result->msg3,
        resp_result->session_keys,
        init_result->msg1,
        resp_result->msg2,
        wrong_pub,
        EcCurve::P256);

    ASSERT_TRUE(verify.has_value());
    EXPECT_FALSE(*verify);
}


TEST_F(SigmaTests, ResponderRejectsTamperedInitiatorMac) {
    constexpr CryptoByte TAMPER_BYTE = 0xFF;

    const auto initiator = ecdsa_generate_key(EcCurve::P256);
    const auto responder = ecdsa_generate_key(EcCurve::P256);
    ASSERT_TRUE(initiator.has_value());
    ASSERT_TRUE(responder.has_value());

    auto init_result = sigma_initiator_begin(EcCurve::P256);
    ASSERT_TRUE(init_result.has_value());

    auto resp_result = sigma_responder_respond(
        init_result->msg1, *responder, EcCurve::P256);
    ASSERT_TRUE(resp_result.has_value());

    SecureBuffer expected_resp_pub(responder->public_key_der.size());
    std::ranges::copy(responder->public_key_der, expected_resp_pub.begin());

    auto finish_result = sigma_initiator_finish(
        std::move(init_result->state),
        resp_result->msg2,
        *initiator,
        expected_resp_pub,
        EcCurve::P256);
    ASSERT_TRUE(finish_result.has_value());

    finish_result->msg3.mac_i[0] ^= TAMPER_BYTE;  // NOLINT(cppcoreguidelines-pro-bounds-avoid-unchecked-container-access)

    SecureBuffer expected_init_pub(initiator->public_key_der.size());
    std::ranges::copy(initiator->public_key_der, expected_init_pub.begin());

    const auto verify = sigma_responder_finish(
        finish_result->msg3,
        resp_result->session_keys,
        init_result->msg1,
        resp_result->msg2,
        expected_init_pub,
        EcCurve::P256);

    ASSERT_TRUE(verify.has_value());
    EXPECT_FALSE(*verify);
}


TEST_F(SigmaTests, ResponderRejectsTamperedInitiatorSignature) {
    constexpr CryptoByte TAMPER_BYTE = 0xFF;

    const auto initiator = ecdsa_generate_key(EcCurve::P256);
    const auto responder = ecdsa_generate_key(EcCurve::P256);
    ASSERT_TRUE(initiator.has_value());
    ASSERT_TRUE(responder.has_value());

    auto init_result = sigma_initiator_begin(EcCurve::P256);
    ASSERT_TRUE(init_result.has_value());

    auto resp_result = sigma_responder_respond(
        init_result->msg1, *responder, EcCurve::P256);
    ASSERT_TRUE(resp_result.has_value());

    SecureBuffer expected_resp_pub(responder->public_key_der.size());
    std::ranges::copy(responder->public_key_der, expected_resp_pub.begin());

    auto finish_result = sigma_initiator_finish(
        std::move(init_result->state),
        resp_result->msg2,
        *initiator,
        expected_resp_pub,
        EcCurve::P256);
    ASSERT_TRUE(finish_result.has_value());

    finish_result->msg3.signature_i[0] ^= TAMPER_BYTE;  // NOLINT(cppcoreguidelines-pro-bounds-avoid-unchecked-container-access)

    SecureBuffer expected_init_pub(initiator->public_key_der.size());
    std::ranges::copy(initiator->public_key_der, expected_init_pub.begin());

    const auto verify = sigma_responder_finish(
        finish_result->msg3,
        resp_result->session_keys,
        init_result->msg1,
        resp_result->msg2,
        expected_init_pub,
        EcCurve::P256);

    ASSERT_TRUE(verify.has_value());
    EXPECT_FALSE(*verify);
}


// Tamper with the initiator's ephemeral public key in Msg1 before the
// responder processes it.  The two parties compute different ECDH shared
// secrets, so the MAC key diverges and the initiator rejects Msg2.
TEST_F(SigmaTests, InitiatorRejectsTamperedEphemeralPubInMsg1) {
    constexpr CryptoByte TAMPER_BYTE = 0xFF;

    const auto initiator = ecdsa_generate_key(EcCurve::P256);
    const auto responder = ecdsa_generate_key(EcCurve::P256);
    ASSERT_TRUE(initiator.has_value());
    ASSERT_TRUE(responder.has_value());

    auto init_result = sigma_initiator_begin(EcCurve::P256);
    ASSERT_TRUE(init_result.has_value());

    // Corrupt the ephemeral public key before the responder sees it.
    init_result->msg1.ephemeral_pub_i[1] ^= TAMPER_BYTE;  // NOLINT(cppcoreguidelines-pro-bounds-avoid-unchecked-container-access)

    auto resp_result = sigma_responder_respond(
        init_result->msg1, *responder, EcCurve::P256);
    // Responder may fail immediately (bad point) or succeed with a wrong shared secret.
    if (!resp_result.has_value()) { return; }

    SecureBuffer expected_pub(responder->public_key_der.size());
    std::ranges::copy(responder->public_key_der, expected_pub.begin());

    const auto finish = sigma_initiator_finish(
        std::move(init_result->state),
        resp_result->msg2,
        *initiator,
        expected_pub,
        EcCurve::P256);

    // Initiator must reject: MAC verification will fail because the two
    // parties derived their keys from different shared secrets.
    EXPECT_FALSE(finish.has_value());
}


// Tamper with the responder's ephemeral public key in Msg2.  The initiator
// computes ECDH with a different point than the responder used, so the derived
// keys diverge and the initiator cannot verify the responder's MAC.
TEST_F(SigmaTests, InitiatorRejectsTamperedEphemeralPubInMsg2) {
    constexpr CryptoByte TAMPER_BYTE = 0xFF;

    const auto initiator = ecdsa_generate_key(EcCurve::P256);
    const auto responder = ecdsa_generate_key(EcCurve::P256);
    ASSERT_TRUE(initiator.has_value());
    ASSERT_TRUE(responder.has_value());

    auto init_result = sigma_initiator_begin(EcCurve::P256);
    ASSERT_TRUE(init_result.has_value());

    auto resp_result = sigma_responder_respond(
        init_result->msg1, *responder, EcCurve::P256);
    ASSERT_TRUE(resp_result.has_value());

    // Corrupt the responder's ephemeral public key.
    resp_result->msg2.ephemeral_pub_r[1] ^= TAMPER_BYTE;  // NOLINT(cppcoreguidelines-pro-bounds-avoid-unchecked-container-access)

    SecureBuffer expected_pub(responder->public_key_der.size());
    std::ranges::copy(responder->public_key_der, expected_pub.begin());

    const auto finish = sigma_initiator_finish(
        std::move(init_result->state),
        resp_result->msg2,
        *initiator,
        expected_pub,
        EcCurve::P256);

    ASSERT_FALSE(finish.has_value());
    EXPECT_EQ(finish.error().code(), CryptoErrorCode::SigmaAuthFailed);
}


// After a successful handshake the session keys on both sides are identical,
// so data encrypted by one party can be decrypted by the other.
TEST_F(SigmaTests, SessionKeyCanBeUsedToEncryptAndDecrypt) {
    const auto initiator = ecdsa_generate_key(EcCurve::P256);
    const auto responder = ecdsa_generate_key(EcCurve::P256);
    ASSERT_TRUE(initiator.has_value());
    ASSERT_TRUE(responder.has_value());

    const auto result = run_handshake(*initiator, *responder, EcCurve::P256);

    // Copy session keys into fixed-size buffers required by the AES-GCM API.
    ASSERT_EQ(result.initiator_keys.session_key.size(), aes256_key_size_bytes);
    FixedSecureBuffer<aes256_key_size_bytes> init_key{};
    std::ranges::copy(result.initiator_keys.session_key, init_key.begin());

    ASSERT_EQ(result.responder_keys.session_key.size(), aes256_key_size_bytes);
    FixedSecureBuffer<aes256_key_size_bytes> resp_key{};
    std::ranges::copy(result.responder_keys.session_key, resp_key.begin());

    // Initiator encrypts a known plaintext with its session key.
    constexpr std::array<CryptoByte, 8> raw_plaintext = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    SecureBuffer plaintext(raw_plaintext.size());
    std::ranges::copy(raw_plaintext, plaintext.begin());
    const auto enc = aes256_gcm_encrypt(init_key, plaintext, {});
    ASSERT_TRUE(enc.has_value());

    // Responder decrypts using its (identical) session key.
    const auto dec = aes256_gcm_decrypt(resp_key, *enc, {});
    ASSERT_TRUE(dec.has_value());

    ASSERT_EQ(dec->size(), plaintext.size());
    EXPECT_TRUE(std::ranges::equal(*dec, plaintext));
}


// Replaying Msg2 from one handshake into a different initiator session (with a
// different ephemeral private key) must be rejected: the initiator computes
// ECDH over a different shared secret, so the MAC in Msg2 won't verify.
TEST_F(SigmaTests, InitiatorRejectsReplayedMsg2FromDifferentSession) {
    const auto initiator = ecdsa_generate_key(EcCurve::P256);
    const auto responder = ecdsa_generate_key(EcCurve::P256);
    ASSERT_TRUE(initiator.has_value());
    ASSERT_TRUE(responder.has_value());

    // Session A: run only up through Msg2.
    auto init_a = sigma_initiator_begin(EcCurve::P256);
    ASSERT_TRUE(init_a.has_value());
    auto resp_a = sigma_responder_respond(init_a->msg1, *responder, EcCurve::P256);
    ASSERT_TRUE(resp_a.has_value());

    // Session B: a fresh initiator state with a different ephemeral key pair.
    auto init_b = sigma_initiator_begin(EcCurve::P256);
    ASSERT_TRUE(init_b.has_value());

    SecureBuffer expected_pub(responder->public_key_der.size());
    std::ranges::copy(responder->public_key_der, expected_pub.begin());

    // Feed session A's Msg2 into session B's initiator — must fail.
    const auto finish = sigma_initiator_finish(
        std::move(init_b->state),
        resp_a->msg2,
        *initiator,
        expected_pub,
        EcCurve::P256);

    ASSERT_FALSE(finish.has_value());
    EXPECT_EQ(finish.error().code(), CryptoErrorCode::SigmaAuthFailed);
}


// Two independent handshakes use different ephemeral key pairs and therefore
// derive different session keys.
TEST_F(SigmaTests, FreshHandshakesProduceDifferentSessionKeys) {
    const auto initiator = ecdsa_generate_key(EcCurve::P256);
    const auto responder = ecdsa_generate_key(EcCurve::P256);
    ASSERT_TRUE(initiator.has_value());
    ASSERT_TRUE(responder.has_value());

    const auto result1 = run_handshake(*initiator, *responder, EcCurve::P256);
    const auto result2 = run_handshake(*initiator, *responder, EcCurve::P256);

    ASSERT_EQ(result1.initiator_keys.session_key.size(),
              result2.initiator_keys.session_key.size());
    EXPECT_FALSE(std::ranges::equal(
        std::span(result1.initiator_keys.session_key.data(),
                  result1.initiator_keys.session_key.size()),
        std::span(result2.initiator_keys.session_key.data(),
                  result2.initiator_keys.session_key.size())));
}
