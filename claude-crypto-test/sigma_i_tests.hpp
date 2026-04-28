/*
Copyright Permanence AI, 2026. All rights reserved.

*/

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
