// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <algorithm>
#include <cstddef>
#include <span>

#include <gtest/gtest.h>

#include "ecdh.hpp"
#include "test_utils.hpp"


class EcdhTests : public ::testing::Test {
};


TEST_F(EcdhTests, GenerateKeyP256ProducesValidKeyPair) {
    const auto key_pair = ecdh_generate_key(EcCurve::P256);

    ASSERT_TRUE(key_pair.has_value());
    EXPECT_FALSE(key_pair->private_key_der.empty());
    EXPECT_FALSE(key_pair->public_key_der.empty());
}


TEST_F(EcdhTests, GenerateKeyP384ProducesValidKeyPair) {
    const auto key_pair = ecdh_generate_key(EcCurve::P384);

    ASSERT_TRUE(key_pair.has_value());
    EXPECT_FALSE(key_pair->private_key_der.empty());
    EXPECT_FALSE(key_pair->public_key_der.empty());
}


TEST_F(EcdhTests, GenerateKeyP521ProducesValidKeyPair) {
    const auto key_pair = ecdh_generate_key(EcCurve::P521);

    ASSERT_TRUE(key_pair.has_value());
    EXPECT_FALSE(key_pair->private_key_der.empty());
    EXPECT_FALSE(key_pair->public_key_der.empty());
}


TEST_F(EcdhTests, P256SharedSecretAgreementIsSymmetric) {
    const auto alice = ecdh_generate_key(EcCurve::P256);
    const auto bob   = ecdh_generate_key(EcCurve::P256);
    ASSERT_TRUE(alice.has_value());
    ASSERT_TRUE(bob.has_value());

    const auto alice_secret = ecdh_compute_shared_secret(*alice, EcCurve::P256, bob->public_key_der);
    const auto bob_secret   = ecdh_compute_shared_secret(*bob,   EcCurve::P256, alice->public_key_der);
    ASSERT_TRUE(alice_secret.has_value());
    ASSERT_TRUE(bob_secret.has_value());

    ASSERT_EQ(alice_secret->size(), bob_secret->size());
    EXPECT_TRUE(std::ranges::equal(
        std::span(alice_secret->data(), alice_secret->size()),
        std::span(bob_secret->data(),   bob_secret->size())));
}


TEST_F(EcdhTests, P384SharedSecretAgreementIsSymmetric) {
    const auto alice = ecdh_generate_key(EcCurve::P384);
    const auto bob   = ecdh_generate_key(EcCurve::P384);
    ASSERT_TRUE(alice.has_value());
    ASSERT_TRUE(bob.has_value());

    const auto alice_secret = ecdh_compute_shared_secret(*alice, EcCurve::P384, bob->public_key_der);
    const auto bob_secret   = ecdh_compute_shared_secret(*bob,   EcCurve::P384, alice->public_key_der);
    ASSERT_TRUE(alice_secret.has_value());
    ASSERT_TRUE(bob_secret.has_value());

    ASSERT_EQ(alice_secret->size(), bob_secret->size());
    EXPECT_TRUE(std::ranges::equal(
        std::span(alice_secret->data(), alice_secret->size()),
        std::span(bob_secret->data(),   bob_secret->size())));
}


TEST_F(EcdhTests, P521SharedSecretAgreementIsSymmetric) {
    const auto alice = ecdh_generate_key(EcCurve::P521);
    const auto bob   = ecdh_generate_key(EcCurve::P521);
    ASSERT_TRUE(alice.has_value());
    ASSERT_TRUE(bob.has_value());

    const auto alice_secret = ecdh_compute_shared_secret(*alice, EcCurve::P521, bob->public_key_der);
    const auto bob_secret   = ecdh_compute_shared_secret(*bob,   EcCurve::P521, alice->public_key_der);
    ASSERT_TRUE(alice_secret.has_value());
    ASSERT_TRUE(bob_secret.has_value());

    ASSERT_EQ(alice_secret->size(), bob_secret->size());
    EXPECT_TRUE(std::ranges::equal(
        std::span(alice_secret->data(), alice_secret->size()),
        std::span(bob_secret->data(),   bob_secret->size())));
}


TEST_F(EcdhTests, P256SharedSecretHasExpectedSize) {
    const auto alice = ecdh_generate_key(EcCurve::P256);
    const auto bob   = ecdh_generate_key(EcCurve::P256);
    ASSERT_TRUE(alice.has_value());
    ASSERT_TRUE(bob.has_value());

    const auto secret = ecdh_compute_shared_secret(*alice, EcCurve::P256, bob->public_key_der);
    ASSERT_TRUE(secret.has_value());
    EXPECT_EQ(secret->size(), ecdh_p256_shared_secret_bytes);
}


TEST_F(EcdhTests, P384SharedSecretHasExpectedSize) {
    const auto alice = ecdh_generate_key(EcCurve::P384);
    const auto bob   = ecdh_generate_key(EcCurve::P384);
    ASSERT_TRUE(alice.has_value());
    ASSERT_TRUE(bob.has_value());

    const auto secret = ecdh_compute_shared_secret(*alice, EcCurve::P384, bob->public_key_der);
    ASSERT_TRUE(secret.has_value());
    EXPECT_EQ(secret->size(), ecdh_p384_shared_secret_bytes);
}


TEST_F(EcdhTests, P521SharedSecretHasExpectedSize) {
    const auto alice = ecdh_generate_key(EcCurve::P521);
    const auto bob   = ecdh_generate_key(EcCurve::P521);
    ASSERT_TRUE(alice.has_value());
    ASSERT_TRUE(bob.has_value());

    const auto secret = ecdh_compute_shared_secret(*alice, EcCurve::P521, bob->public_key_der);
    ASSERT_TRUE(secret.has_value());
    EXPECT_EQ(secret->size(), ecdh_p521_shared_secret_bytes);
}


TEST_F(EcdhTests, DifferentPeersProduceDifferentSecrets) {
    const auto alice = ecdh_generate_key(EcCurve::P256);
    const auto bob   = ecdh_generate_key(EcCurve::P256);
    const auto carol = ecdh_generate_key(EcCurve::P256);
    ASSERT_TRUE(alice.has_value());
    ASSERT_TRUE(bob.has_value());
    ASSERT_TRUE(carol.has_value());

    const auto secret_ab = ecdh_compute_shared_secret(*alice, EcCurve::P256, bob->public_key_der);
    const auto secret_ac = ecdh_compute_shared_secret(*alice, EcCurve::P256, carol->public_key_der);
    ASSERT_TRUE(secret_ab.has_value());
    ASSERT_TRUE(secret_ac.has_value());

    EXPECT_FALSE(std::ranges::equal(
        std::span(secret_ab->data(), secret_ab->size()),
        std::span(secret_ac->data(), secret_ac->size())));
}


TEST_F(EcdhTests, InvalidPeerPublicKeyReturnsError) {
    const auto alice = ecdh_generate_key(EcCurve::P256);
    ASSERT_TRUE(alice.has_value());

    const auto garbage = make_random_secure_buffer(65);
    const auto result  = ecdh_compute_shared_secret(*alice, EcCurve::P256, garbage);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), CryptoErrorCode::KeyAgreementFailed);
    EXPECT_FALSE(result.error().message().empty());
}
