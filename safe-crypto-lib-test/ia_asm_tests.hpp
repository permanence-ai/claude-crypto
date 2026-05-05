/*
Copyright Permanence AI, 2026. All rights reserved.

*/

#pragma once

// IA ASM backend regression tests.
// Guarded by SAFE_CRYPTO_PROVIDER_IA_ASM so they only run when that backend is active.

#include <array>
#include <cstdint>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#ifdef SAFE_CRYPTO_PROVIDER_IA_ASM

#include "ia_asm_backend.hpp"

// ---------------------------------------------------------------------------
// IaAsmEcdhValidationTests — Issue #6: reject invalid ECDH peer points.
// Mirrors ArmAsmEcdhValidationTests in arm_asm_tests.hpp.
// ---------------------------------------------------------------------------

class IaAsmEcdhValidationTests : public ::testing::Test {
protected:
    void TearDown() override {
        for (unsigned int i = 0; i < static_cast<unsigned int>(arm_asm::detail::ec_key_store_capacity); ++i) {
            arm_asm::detail::ec_key_store_destroy(arm_asm::detail::ec_key_id_base + i);
        }
    }

    static IaAsmBackend::KeyId generate_ecdh_key(arm_asm::detail::EcCurveId curve) {
        std::size_t bits = 0;
        if (curve == arm_asm::detail::EcCurveId::P256) { bits = 256; } // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        else if (curve == arm_asm::detail::EcCurveId::P384) { bits = 384; } // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        else { bits = 521; } // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        auto attrs = IaAsmBackend::make_ecdh_generate_attrs(bits);
        IaAsmBackend::KeyId id = IaAsmBackend::null_key_id();
        if (IaAsmBackend::generate_key(&attrs, &id) != IaAsmBackend::ok) { return IaAsmBackend::null_key_id(); }
        return id;
    }

    static std::vector<uint8_t> export_public(IaAsmBackend::KeyId id, std::size_t pk_len) {
        std::vector<uint8_t> buf(pk_len);
        std::size_t out_len = 0;
        if (IaAsmBackend::export_public_key(id, buf.data(), buf.size(), &out_len) != IaAsmBackend::ok) { return {}; }
        buf.resize(out_len);
        return buf;
    }
};

// P-256

TEST_F(IaAsmEcdhValidationTests, P256ValidPeerSucceeds) {
    const auto id = generate_ecdh_key(arm_asm::detail::EcCurveId::P256);
    ASSERT_NE(id, IaAsmBackend::null_key_id());
    auto peer = export_public(id, 65); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ASSERT_EQ(peer.size(), 65U);
    std::array<uint8_t, 32> out{};
    std::size_t out_len = 0;
    EXPECT_EQ(IaAsmBackend::raw_key_agreement(IaAsmBackend::alg_ecdh(), id,
                                               peer.data(), peer.size(),
                                               out.data(), out.size(), &out_len),
              IaAsmBackend::ok);
}

TEST_F(IaAsmEcdhValidationTests, P256AllZeroPeerReturnsInvalidArg) {
    const auto id = generate_ecdh_key(arm_asm::detail::EcCurveId::P256);
    ASSERT_NE(id, IaAsmBackend::null_key_id());
    std::array<uint8_t, 65> peer{}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    peer[0] = 0x04U;
    std::array<uint8_t, 32> out{};
    std::size_t out_len = 0;
    EXPECT_EQ(IaAsmBackend::raw_key_agreement(IaAsmBackend::alg_ecdh(), id,
                                               peer.data(), peer.size(),
                                               out.data(), out.size(), &out_len),
              IaAsmBackend::err_invalid_arg);
}

TEST_F(IaAsmEcdhValidationTests, P256OffCurvePeerReturnsInvalidArg) {
    const auto id = generate_ecdh_key(arm_asm::detail::EcCurveId::P256);
    ASSERT_NE(id, IaAsmBackend::null_key_id());
    auto peer = export_public(id, 65); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ASSERT_EQ(peer.size(), 65U);
    peer[64] ^= 0x01U; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    std::array<uint8_t, 32> out{};
    std::size_t out_len = 0;
    EXPECT_EQ(IaAsmBackend::raw_key_agreement(IaAsmBackend::alg_ecdh(), id,
                                               peer.data(), peer.size(),
                                               out.data(), out.size(), &out_len),
              IaAsmBackend::err_invalid_arg);
}

// P-384

TEST_F(IaAsmEcdhValidationTests, P384ValidPeerSucceeds) {
    const auto id = generate_ecdh_key(arm_asm::detail::EcCurveId::P384);
    ASSERT_NE(id, IaAsmBackend::null_key_id());
    auto peer = export_public(id, 97); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ASSERT_EQ(peer.size(), 97U);
    std::array<uint8_t, 48> out{}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    std::size_t out_len = 0;
    EXPECT_EQ(IaAsmBackend::raw_key_agreement(IaAsmBackend::alg_ecdh(), id,
                                               peer.data(), peer.size(),
                                               out.data(), out.size(), &out_len),
              IaAsmBackend::ok);
}

TEST_F(IaAsmEcdhValidationTests, P384AllZeroPeerReturnsInvalidArg) {
    const auto id = generate_ecdh_key(arm_asm::detail::EcCurveId::P384);
    ASSERT_NE(id, IaAsmBackend::null_key_id());
    std::array<uint8_t, 97> peer{}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    peer[0] = 0x04U;
    std::array<uint8_t, 48> out{}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    std::size_t out_len = 0;
    EXPECT_EQ(IaAsmBackend::raw_key_agreement(IaAsmBackend::alg_ecdh(), id,
                                               peer.data(), peer.size(),
                                               out.data(), out.size(), &out_len),
              IaAsmBackend::err_invalid_arg);
}

TEST_F(IaAsmEcdhValidationTests, P384OffCurvePeerReturnsInvalidArg) {
    const auto id = generate_ecdh_key(arm_asm::detail::EcCurveId::P384);
    ASSERT_NE(id, IaAsmBackend::null_key_id());
    auto peer = export_public(id, 97); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ASSERT_EQ(peer.size(), 97U);
    peer[96] ^= 0x01U; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    std::array<uint8_t, 48> out{}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    std::size_t out_len = 0;
    EXPECT_EQ(IaAsmBackend::raw_key_agreement(IaAsmBackend::alg_ecdh(), id,
                                               peer.data(), peer.size(),
                                               out.data(), out.size(), &out_len),
              IaAsmBackend::err_invalid_arg);
}

// P-521

TEST_F(IaAsmEcdhValidationTests, P521ValidPeerSucceeds) {
    const auto id = generate_ecdh_key(arm_asm::detail::EcCurveId::P521);
    ASSERT_NE(id, IaAsmBackend::null_key_id());
    auto peer = export_public(id, 133); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ASSERT_EQ(peer.size(), 133U);
    std::array<uint8_t, 66> out{}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    std::size_t out_len = 0;
    EXPECT_EQ(IaAsmBackend::raw_key_agreement(IaAsmBackend::alg_ecdh(), id,
                                               peer.data(), peer.size(),
                                               out.data(), out.size(), &out_len),
              IaAsmBackend::ok);
}

TEST_F(IaAsmEcdhValidationTests, P521AllZeroPeerReturnsInvalidArg) {
    const auto id = generate_ecdh_key(arm_asm::detail::EcCurveId::P521);
    ASSERT_NE(id, IaAsmBackend::null_key_id());
    std::array<uint8_t, 133> peer{}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    peer[0] = 0x04U;
    std::array<uint8_t, 66> out{}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    std::size_t out_len = 0;
    EXPECT_EQ(IaAsmBackend::raw_key_agreement(IaAsmBackend::alg_ecdh(), id,
                                               peer.data(), peer.size(),
                                               out.data(), out.size(), &out_len),
              IaAsmBackend::err_invalid_arg);
}

TEST_F(IaAsmEcdhValidationTests, P521OffCurvePeerReturnsInvalidArg) {
    const auto id = generate_ecdh_key(arm_asm::detail::EcCurveId::P521);
    ASSERT_NE(id, IaAsmBackend::null_key_id());
    auto peer = export_public(id, 133); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ASSERT_EQ(peer.size(), 133U);
    peer[132] ^= 0x01U; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    std::array<uint8_t, 66> out{}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    std::size_t out_len = 0;
    EXPECT_EQ(IaAsmBackend::raw_key_agreement(IaAsmBackend::alg_ecdh(), id,
                                               peer.data(), peer.size(),
                                               out.data(), out.size(), &out_len),
              IaAsmBackend::err_invalid_arg);
}

TEST_F(IaAsmEcdhValidationTests, P521NonCanonicalHighBitsReturnsInvalidArg) {
    const auto id = generate_ecdh_key(arm_asm::detail::EcCurveId::P521);
    ASSERT_NE(id, IaAsmBackend::null_key_id());
    auto peer = export_public(id, 133); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ASSERT_EQ(peer.size(), 133U);
    peer[1] |= 0x80U; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    std::array<uint8_t, 66> out{}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    std::size_t out_len = 0;
    EXPECT_EQ(IaAsmBackend::raw_key_agreement(IaAsmBackend::alg_ecdh(), id,
                                               peer.data(), peer.size(),
                                               out.data(), out.size(), &out_len),
              IaAsmBackend::err_invalid_arg);
}


// ---------------------------------------------------------------------------
// IaAsmEcdsaSigDecodeTests — Issue #6: reject non-canonical r/s in verify,
// and reject off-curve ECDSA public keys.
// Mirrors ArmAsmEcdsaSigDecodeTests in arm_asm_tests.hpp.
// ---------------------------------------------------------------------------

class IaAsmEcdsaSigDecodeTests : public ::testing::Test {
protected:
    void TearDown() override {
        for (unsigned int i = 0; i < static_cast<unsigned int>(arm_asm::detail::ec_key_store_capacity); ++i) {
            arm_asm::detail::ec_key_store_destroy(arm_asm::detail::ec_key_id_base + i);
        }
    }

    static std::pair<IaAsmBackend::KeyId, IaAsmBackend::KeyId>
    generate_ecdsa_pair(std::size_t bits) {
        auto attrs = IaAsmBackend::make_ecdsa_generate_attrs(bits);
        IaAsmBackend::KeyId priv_id = IaAsmBackend::null_key_id();
        if (IaAsmBackend::generate_key(&attrs, &priv_id) != IaAsmBackend::ok) {
            return {IaAsmBackend::null_key_id(), IaAsmBackend::null_key_id()};
        }
        std::size_t pk_len = 0;
        if (bits == 256) { pk_len = 65; } // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        else if (bits == 384) { pk_len = 97; } // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        else { pk_len = 133; } // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        std::vector<uint8_t> pub_buf(pk_len);
        std::size_t exported = 0;
        if (IaAsmBackend::export_public_key(priv_id, pub_buf.data(), pk_len, &exported) != IaAsmBackend::ok) {
            return {priv_id, IaAsmBackend::null_key_id()};
        }
        const auto curve = (bits == 256) ? arm_asm::detail::EcCurveId::P256 // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
                         : (bits == 384) ? arm_asm::detail::EcCurveId::P384 // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
                                         : arm_asm::detail::EcCurveId::P521;
        const auto pub_id = arm_asm::detail::ec_key_store_import(
            curve, arm_asm::detail::EcKeyKind::Public, pub_buf.data(), exported);
        return {priv_id, static_cast<IaAsmBackend::KeyId>(pub_id)};
    }

    static std::vector<uint8_t> sign(IaAsmBackend::KeyId priv_id, std::size_t sig_len) {
        static constexpr std::array<uint8_t, 64> kMsg{};
        std::vector<uint8_t> sig(sig_len);
        std::size_t out_len = 0;
        if (IaAsmBackend::sign_message(priv_id, IaAsmBackend::alg_ecdsa(),
                                       kMsg.data(), kMsg.size(),
                                       sig.data(), sig.size(), &out_len) != IaAsmBackend::ok) {
            return {};
        }
        sig.resize(out_len);
        return sig;
    }

    static IaAsmBackend::Status verify(IaAsmBackend::KeyId pub_id,
                                       const std::vector<uint8_t>& sig) {
        static constexpr std::array<uint8_t, 64> kMsg{};
        return IaAsmBackend::verify_message(pub_id, IaAsmBackend::alg_ecdsa(),
                                            kMsg.data(), kMsg.size(),
                                            sig.data(), sig.size());
    }
};

// ---- P-256 ----

TEST_F(IaAsmEcdsaSigDecodeTests, P256ValidSignatureVerifies) {
    const auto [priv_id, pub_id] = generate_ecdsa_pair(256); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ASSERT_NE(priv_id, IaAsmBackend::null_key_id());
    ASSERT_NE(pub_id,  IaAsmBackend::null_key_id());
    const auto sig = sign(priv_id, 64); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ASSERT_FALSE(sig.empty());
    EXPECT_EQ(verify(pub_id, sig), IaAsmBackend::ok);
}

TEST_F(IaAsmEcdsaSigDecodeTests, P256ZeroRRejectsSignature) {
    const auto [priv_id, pub_id] = generate_ecdsa_pair(256); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ASSERT_NE(priv_id, IaAsmBackend::null_key_id());
    auto sig = sign(priv_id, 64); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ASSERT_FALSE(sig.empty());
    std::fill(sig.begin(), sig.begin() + 32, 0x00U);
    EXPECT_NE(verify(pub_id, sig), IaAsmBackend::ok);
}

TEST_F(IaAsmEcdsaSigDecodeTests, P256ZeroSRejectsSignature) {
    const auto [priv_id, pub_id] = generate_ecdsa_pair(256); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ASSERT_NE(priv_id, IaAsmBackend::null_key_id());
    auto sig = sign(priv_id, 64); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ASSERT_FALSE(sig.empty());
    std::fill(sig.begin() + 32, sig.end(), 0x00U);
    EXPECT_NE(verify(pub_id, sig), IaAsmBackend::ok);
}

TEST_F(IaAsmEcdsaSigDecodeTests, P256REqualsNRejectsSignature) {
    const auto [priv_id, pub_id] = generate_ecdsa_pair(256); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ASSERT_NE(priv_id, IaAsmBackend::null_key_id());
    auto sig = sign(priv_id, 64); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ASSERT_FALSE(sig.empty());
    static constexpr std::array<uint8_t, 32> kP256N = {{
        0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00, // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        0xBC,0xE6,0xFA,0xAD,0xA7,0x17,0x9E,0x84, // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        0xF3,0xB9,0xCA,0xC2,0xFC,0x63,0x25,0x51  // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    }};
    std::copy(kP256N.begin(), kP256N.end(), sig.begin());
    EXPECT_NE(verify(pub_id, sig), IaAsmBackend::ok);
}

TEST_F(IaAsmEcdsaSigDecodeTests, P256AllOnesRRejectsSignature) {
    const auto [priv_id, pub_id] = generate_ecdsa_pair(256); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ASSERT_NE(priv_id, IaAsmBackend::null_key_id());
    auto sig = sign(priv_id, 64); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ASSERT_FALSE(sig.empty());
    std::fill(sig.begin(), sig.begin() + 32, 0xFFU);
    EXPECT_NE(verify(pub_id, sig), IaAsmBackend::ok);
}

TEST_F(IaAsmEcdsaSigDecodeTests, P256OffCurvePublicKeyRejectsVerify) {
    const auto [priv_id, pub_id] = generate_ecdsa_pair(256); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ASSERT_NE(priv_id, IaAsmBackend::null_key_id());
    const auto sig = sign(priv_id, 64); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ASSERT_FALSE(sig.empty());
    // Export the public key, flip last byte of y to make it off-curve, re-import.
    std::array<uint8_t, 65> pk_buf{}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    std::size_t pk_len = 0;
    ASSERT_EQ(IaAsmBackend::export_public_key(pub_id, pk_buf.data(), pk_buf.size(), &pk_len), IaAsmBackend::ok);
    pk_buf[64] ^= 0x01U; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    const auto bad_pub = static_cast<IaAsmBackend::KeyId>(
        arm_asm::detail::ec_key_store_import(
            arm_asm::detail::EcCurveId::P256, arm_asm::detail::EcKeyKind::Public,
            pk_buf.data(), pk_len));
    ASSERT_NE(bad_pub, IaAsmBackend::null_key_id());
    EXPECT_NE(verify(bad_pub, sig), IaAsmBackend::ok);
}

// ---- P-384 ----

TEST_F(IaAsmEcdsaSigDecodeTests, P384ValidSignatureVerifies) {
    const auto [priv_id, pub_id] = generate_ecdsa_pair(384); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ASSERT_NE(priv_id, IaAsmBackend::null_key_id());
    ASSERT_NE(pub_id,  IaAsmBackend::null_key_id());
    const auto sig = sign(priv_id, 96); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ASSERT_FALSE(sig.empty());
    EXPECT_EQ(verify(pub_id, sig), IaAsmBackend::ok);
}

TEST_F(IaAsmEcdsaSigDecodeTests, P384ZeroRRejectsSignature) {
    const auto [priv_id, pub_id] = generate_ecdsa_pair(384); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ASSERT_NE(priv_id, IaAsmBackend::null_key_id());
    auto sig = sign(priv_id, 96); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ASSERT_FALSE(sig.empty());
    std::fill(sig.begin(), sig.begin() + 48, 0x00U); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    EXPECT_NE(verify(pub_id, sig), IaAsmBackend::ok);
}

TEST_F(IaAsmEcdsaSigDecodeTests, P384REqualsNRejectsSignature) {
    const auto [priv_id, pub_id] = generate_ecdsa_pair(384); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ASSERT_NE(priv_id, IaAsmBackend::null_key_id());
    auto sig = sign(priv_id, 96); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ASSERT_FALSE(sig.empty());
    static constexpr std::array<uint8_t, 48> kP384N = {{ // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        0xC7,0x63,0x4D,0x81,0xF4,0x37,0x2D,0xDF, // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        0x58,0x1A,0x0D,0xB2,0x48,0xB0,0xA7,0x7A, // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        0xEC,0xEC,0x19,0x6A,0xCC,0xC5,0x29,0x73  // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    }};
    std::copy(kP384N.begin(), kP384N.end(), sig.begin());
    EXPECT_NE(verify(pub_id, sig), IaAsmBackend::ok);
}

TEST_F(IaAsmEcdsaSigDecodeTests, P384AllOnesRRejectsSignature) {
    const auto [priv_id, pub_id] = generate_ecdsa_pair(384); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ASSERT_NE(priv_id, IaAsmBackend::null_key_id());
    auto sig = sign(priv_id, 96); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ASSERT_FALSE(sig.empty());
    std::fill(sig.begin(), sig.begin() + 48, 0xFFU); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    EXPECT_NE(verify(pub_id, sig), IaAsmBackend::ok);
}

// ---- P-521 ----

TEST_F(IaAsmEcdsaSigDecodeTests, P521ValidSignatureVerifies) {
    const auto [priv_id, pub_id] = generate_ecdsa_pair(521); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ASSERT_NE(priv_id, IaAsmBackend::null_key_id());
    ASSERT_NE(pub_id,  IaAsmBackend::null_key_id());
    const auto sig = sign(priv_id, 132); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ASSERT_FALSE(sig.empty());
    EXPECT_EQ(verify(pub_id, sig), IaAsmBackend::ok);
}

TEST_F(IaAsmEcdsaSigDecodeTests, P521ZeroRRejectsSignature) {
    const auto [priv_id, pub_id] = generate_ecdsa_pair(521); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ASSERT_NE(priv_id, IaAsmBackend::null_key_id());
    auto sig = sign(priv_id, 132); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ASSERT_FALSE(sig.empty());
    std::fill(sig.begin(), sig.begin() + 66, 0x00U); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    EXPECT_NE(verify(pub_id, sig), IaAsmBackend::ok);
}

TEST_F(IaAsmEcdsaSigDecodeTests, P521REqualsNRejectsSignature) {
    const auto [priv_id, pub_id] = generate_ecdsa_pair(521); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ASSERT_NE(priv_id, IaAsmBackend::null_key_id());
    auto sig = sign(priv_id, 132); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ASSERT_FALSE(sig.empty());
    static constexpr std::array<uint8_t, 66> kP521N = {{ // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        0x01,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        0xFF,0xFA,0x51,0x86,0x87,0x83,0xBF,0x2F, // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        0x96,0x6B,0x7F,0xCC,0x01,0x48,0xF7,0x09, // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        0xA5,0xD0,0x3B,0xB5,0xC9,0xB8,0x89,0x9C, // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        0x47,0xAE,0xBB,0x6F,0xB7,0x1E,0x91,0x38, // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        0x64,0x09                                  // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    }};
    std::copy(kP521N.begin(), kP521N.end(), sig.begin());
    EXPECT_NE(verify(pub_id, sig), IaAsmBackend::ok);
}

TEST_F(IaAsmEcdsaSigDecodeTests, P521RHighBitSetRejectsSignature) {
    const auto [priv_id, pub_id] = generate_ecdsa_pair(521); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ASSERT_NE(priv_id, IaAsmBackend::null_key_id());
    auto sig = sign(priv_id, 132); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ASSERT_FALSE(sig.empty());
    sig[0] |= 0x80U;
    EXPECT_NE(verify(pub_id, sig), IaAsmBackend::ok);
}

TEST_F(IaAsmEcdsaSigDecodeTests, P521SHighBitSetRejectsSignature) {
    const auto [priv_id, pub_id] = generate_ecdsa_pair(521); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ASSERT_NE(priv_id, IaAsmBackend::null_key_id());
    auto sig = sign(priv_id, 132); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ASSERT_FALSE(sig.empty());
    sig[66] |= 0x80U; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    EXPECT_NE(verify(pub_id, sig), IaAsmBackend::ok);
}

#endif  // SAFE_CRYPTO_PROVIDER_IA_ASM
