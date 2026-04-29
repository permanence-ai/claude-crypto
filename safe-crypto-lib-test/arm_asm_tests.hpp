/*
Copyright Permanence AI, 2026. All rights reserved.

*/

#pragma once

// Known-answer-vector tests for the ARM ASM provider.
// Compiled into every build but the inner tests are guarded by
// SAFE_CRYPTO_PROVIDER_ARM_ASM so they only run when that backend is active.

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include <gtest/gtest.h>

#include "defs.hpp"
#include "secure_buffer.hpp"

#ifdef SAFE_CRYPTO_PROVIDER_ARM_ASM

#include "aes256_gcm.hpp"
#include "arm_asm_backend.hpp"
#include "hkdf.hpp"
#include "kdf.hpp"

// ---------------------------------------------------------------------------
// NIST SP 800-38D AES-256-GCM test vectors
// Source: NIST CAVP gcmEncryptExtIV256.rsp — first two cases with non-empty
// plaintext and no AAD (Case 1), and one case with non-empty AAD (Case 2).
//
// Vector 1 (NIST Case 1, no AAD, PT=0 bytes, just testing tag):
//   Key : 0000…00 (32 zero bytes)
//   IV  : 000000000000000000000000
//   PT  : (empty)
//   CT  : (empty)
//   Tag : 530f8afbc74536b9a963b4f1c4cb738b
//
// Vector 2 (NIST gcmEncryptExtIV256, Count=0):
//   Key : feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308
//   IV  : cafebabefacedbaddecaf888
//   PT  : d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72
//         1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255
//         (64 bytes)
//   CT  : 522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa
//         8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad
//         (64 bytes)
//   Tag : b094dac5d93471bdec1a502270e3cc6c
//
// Vector 3 (with AAD, NIST gcmEncryptExtIV256 Count=0 from AAD test file):
//   Key : feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308
//   IV  : cafebabefacedbaddecaf888
//   AAD : feedfacedeadbeeffeedfacedeadbeefabaddad2
//   PT  : d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72
//         1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39 (60 bytes)
//   CT  : 522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa
//         8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662 (60 bytes)
//   Tag : 76fc6ece0f4e1768cddf8853bb2d551b
// ---------------------------------------------------------------------------

class ArmAsmAesGcmVectorTests : public ::testing::Test {
protected:
    static std::array<uint8_t, 32> from_hex32(const char* s) {
        std::array<uint8_t, 32> out{};
        for (std::size_t i = 0; i < 32; ++i) {
            unsigned v = 0;
            // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
            std::sscanf(s + i * 2, "%02x", &v); // NOLINT(cert-err34-c)
            // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
            out[i] = static_cast<uint8_t>(v);
        }
        return out;
    }

    template<std::size_t N>
    static std::array<uint8_t, N> from_hex(const char* s) {
        std::array<uint8_t, N> out{};
        for (std::size_t i = 0; i < N; ++i) {
            unsigned v = 0;
            // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
            std::sscanf(s + i * 2, "%02x", &v); // NOLINT(cert-err34-c)
            // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
            out[i] = static_cast<uint8_t>(v);
        }
        return out;
    }
};


TEST_F(ArmAsmAesGcmVectorTests, ZeroKeyIvEmptyPlaintext) {
    const auto key = from_hex32("0000000000000000000000000000000000000000000000000000000000000000");
    const auto iv  = from_hex<12>("000000000000000000000000");
    const auto expected_tag = from_hex<16>("530f8afbc74536b9a963b4f1c4cb738b");

    // encrypt_output_size(0) = 16 (tag only)
    std::array<uint8_t, 16> out{};
    arm_asm::detail::aes256_gcm_encrypt(key.data(), iv.data(), nullptr, 0,
                                         nullptr, 0, out.data());
    for (std::size_t i = 0; i < 16; ++i) {
        EXPECT_EQ(out[i], expected_tag[i]) << "tag byte " << i; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    }
}


TEST_F(ArmAsmAesGcmVectorTests, Nist256Vector1EncryptNoAad) {
    const auto key = from_hex32(
        "feffe9928665731c6d6a8f9467308308"
        "feffe9928665731c6d6a8f9467308308");
    const auto iv = from_hex<12>("cafebabefacedbaddecaf888");

    // 64-byte plaintext
    const auto pt = from_hex<64>(
        "d9313225f88406e5a55909c5aff5269a"
        "86a7a9531534f7da2e4c303d8a318a72"
        "1c3c0c95956809532fcf0e2449a6b525"
        "b16aedf5aa0de657ba637b391aafd255");

    const auto expected_ct = from_hex<64>(
        "522dc1f099567d07f47f37a32a84427d"
        "643a8cdcbfe5c0c97598a2bd2555d1aa"
        "8cb08e48590dbb3da7b08b1056828838"
        "c5f61e6393ba7a0abcc9f662898015ad");

    const auto expected_tag = from_hex<16>("b094dac5d93471bdec1a502270e3cc6c");

    std::array<uint8_t, 80> out{}; // 64 + 16
    arm_asm::detail::aes256_gcm_encrypt(key.data(), iv.data(), nullptr, 0,
                                         pt.data(), pt.size(), out.data());

    for (std::size_t i = 0; i < 64; ++i) {
        EXPECT_EQ(out[i], expected_ct[i]) << "ct byte " << i; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    }
    for (std::size_t i = 0; i < 16; ++i) {
        EXPECT_EQ(out[64 + i], expected_tag[i]) << "tag byte " << i; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index,cppcoreguidelines-avoid-magic-numbers)
    }
}


TEST_F(ArmAsmAesGcmVectorTests, Nist256Vector1DecryptNoAad) {
    const auto key = from_hex32(
        "feffe9928665731c6d6a8f9467308308"
        "feffe9928665731c6d6a8f9467308308");
    const auto iv = from_hex<12>("cafebabefacedbaddecaf888");

    const auto expected_pt = from_hex<64>(
        "d9313225f88406e5a55909c5aff5269a"
        "86a7a9531534f7da2e4c303d8a318a72"
        "1c3c0c95956809532fcf0e2449a6b525"
        "b16aedf5aa0de657ba637b391aafd255");

    // ct ‖ tag (80 bytes = 64 CT + 16 tag)
    std::array<uint8_t, 80> ct_tag{};
    const auto ct = from_hex<64>(
        "522dc1f099567d07f47f37a32a84427d"
        "643a8cdcbfe5c0c97598a2bd2555d1aa"
        "8cb08e48590dbb3da7b08b1056828838"
        "c5f61e6393ba7a0abcc9f662898015ad");
    const auto tag = from_hex<16>("b094dac5d93471bdec1a502270e3cc6c");
    std::memcpy(ct_tag.data(), ct.data(), 64); // NOLINT(cppcoreguidelines-avoid-magic-numbers)
    std::memcpy(ct_tag.data() + 64, tag.data(), 16); // NOLINT(cppcoreguidelines-avoid-magic-numbers)

    std::array<uint8_t, 64> pt{};
    const bool ok = arm_asm::detail::aes256_gcm_decrypt(
        key.data(), iv.data(), nullptr, 0,
        ct_tag.data(), ct_tag.size(), pt.data());

    ASSERT_TRUE(ok);
    for (std::size_t i = 0; i < 64; ++i) {
        EXPECT_EQ(pt[i], expected_pt[i]) << "pt byte " << i; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    }
}


TEST_F(ArmAsmAesGcmVectorTests, Nist256Vector2EncryptWithAad) {
    const auto key = from_hex32(
        "feffe9928665731c6d6a8f9467308308"
        "feffe9928665731c6d6a8f9467308308");
    const auto iv  = from_hex<12>("cafebabefacedbaddecaf888");
    const auto aad = from_hex<20>("feedfacedeadbeeffeedfacedeadbeefabaddad2");

    const auto pt = from_hex<60>(
        "d9313225f88406e5a55909c5aff5269a"
        "86a7a9531534f7da2e4c303d8a318a72"
        "1c3c0c95956809532fcf0e2449a6b525"
        "b16aedf5aa0de657ba637b39");

    const auto expected_ct = from_hex<60>(
        "522dc1f099567d07f47f37a32a84427d"
        "643a8cdcbfe5c0c97598a2bd2555d1aa"
        "8cb08e48590dbb3da7b08b1056828838"
        "c5f61e6393ba7a0abcc9f662");

    const auto expected_tag = from_hex<16>("76fc6ece0f4e1768cddf8853bb2d551b");

    std::array<uint8_t, 76> out{}; // 60 + 16
    arm_asm::detail::aes256_gcm_encrypt(
        key.data(), iv.data(),
        aad.data(), aad.size(),
        pt.data(), pt.size(),
        out.data());

    for (std::size_t i = 0; i < 60; ++i) {
        EXPECT_EQ(out[i], expected_ct[i]) << "ct byte " << i; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    }
    for (std::size_t i = 0; i < 16; ++i) {
        EXPECT_EQ(out[60 + i], expected_tag[i]) << "tag byte " << i; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index,cppcoreguidelines-avoid-magic-numbers)
    }
}


TEST_F(ArmAsmAesGcmVectorTests, TamperedTagRejected) {
    const auto key = from_hex32(
        "feffe9928665731c6d6a8f9467308308"
        "feffe9928665731c6d6a8f9467308308");
    const auto iv = from_hex<12>("cafebabefacedbaddecaf888");

    std::array<uint8_t, 80> ct_tag{};
    const auto ct = from_hex<64>(
        "522dc1f099567d07f47f37a32a84427d"
        "643a8cdcbfe5c0c97598a2bd2555d1aa"
        "8cb08e48590dbb3da7b08b1056828838"
        "c5f61e6393ba7a0abcc9f662898015ad");
    const auto tag = from_hex<16>("b094dac5d93471bdec1a502270e3cc6c");
    std::memcpy(ct_tag.data(), ct.data(), 64); // NOLINT(cppcoreguidelines-avoid-magic-numbers)
    std::memcpy(ct_tag.data() + 64, tag.data(), 16); // NOLINT(cppcoreguidelines-avoid-magic-numbers)
    ct_tag[0] ^= 0xFFU; // tamper first ciphertext byte

    std::array<uint8_t, 64> pt{};
    const bool ok = arm_asm::detail::aes256_gcm_decrypt(
        key.data(), iv.data(), nullptr, 0,
        ct_tag.data(), ct_tag.size(), pt.data());

    EXPECT_FALSE(ok);
    // Output must be zeroed after auth failure.
    for (std::size_t i = 0; i < 64; ++i) {
        EXPECT_EQ(pt[i], 0) << "pt[" << i << "] not zeroized"; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    }
}

// ---------------------------------------------------------------------------
// Phase 6: HKDF tests
// ---------------------------------------------------------------------------

class ArmAsmHkdfTests : public ::testing::Test {
protected:
    template<std::size_t N>
    static std::array<uint8_t, N> from_hex(const char* s) {
        std::array<uint8_t, N> out{};
        for (std::size_t i = 0; i < N; ++i) {
            unsigned v = 0;
            // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
            std::sscanf(s + i * 2, "%02x", &v); // NOLINT(cert-err34-c)
            // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
            out[i] = static_cast<uint8_t>(v);
        }
        return out;
    }
};

// RFC 5869 Test Case 1 with SHA-384 (Python-verified):
//   IKM  = 0x0b0b...0b (22 bytes)
//   salt = 0x000102...0c (13 bytes)
//   info = 0xf0f1...f9 (10 bytes)
//   L    = 42
//   PRK  = 704b39...e8dec70ee9... (48 bytes)
//   OKM  = 9b5097...fc5 (42 bytes)
TEST_F(ArmAsmHkdfTests, Rfc5869Tc1Sha384) {
    const auto ikm  = from_hex<22>("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    const auto salt = from_hex<13>("000102030405060708090a0b0c");
    const auto info = from_hex<10>("f0f1f2f3f4f5f6f7f8f9");
    const auto expected_okm = from_hex<42>(
        "9b5097a86038b805309076a44b3a9f38"
        "063e25b516dcbf369f394cfab43685f7"
        "48b6457763e4f0204fc5");

    // Import IKM, run full HKDF via the state machine.
    auto attrs = ArmAsmBackend::make_hkdf_derive_attrs(ikm.size() * 8U);
    ArmAsmBackend::KeyId id = ArmAsmBackend::null_key_id();
    ASSERT_EQ(ArmAsmBackend::import_key(&attrs, ikm.data(), ikm.size(), &id),
              ArmAsmBackend::ok);

    auto op = ArmAsmBackend::make_kdf_op();
    ASSERT_EQ(ArmAsmBackend::key_derivation_setup(&op, ArmAsmBackend::alg_hkdf()),
              ArmAsmBackend::ok);
    ASSERT_EQ(ArmAsmBackend::key_derivation_input_bytes(
                  &op, ArmAsmBackend::kdf_step_salt(), salt.data(), salt.size()),
              ArmAsmBackend::ok);
    ASSERT_EQ(ArmAsmBackend::key_derivation_input_key(
                  &op, ArmAsmBackend::kdf_step_secret(), id),
              ArmAsmBackend::ok);
    ASSERT_EQ(ArmAsmBackend::key_derivation_input_bytes(
                  &op, ArmAsmBackend::kdf_step_info(), info.data(), info.size()),
              ArmAsmBackend::ok);

    std::array<uint8_t, 42> okm{};
    ASSERT_EQ(ArmAsmBackend::key_derivation_output_bytes(&op, okm.data(), okm.size()),
              ArmAsmBackend::ok);
    ArmAsmBackend::key_derivation_abort(&op);
    ArmAsmBackend::destroy_key(id);

    for (std::size_t i = 0; i < 42; ++i) {
        EXPECT_EQ(okm[i], expected_okm[i]) << "OKM byte " << i; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    }
}

// RFC 5869 Test Case 2 with SHA-384: no salt, no info, L=42.
//   IKM  = 0x0b0b...0b (22 bytes)
//   OKM  = c8c96e...ca68bc... (42 bytes)
TEST_F(ArmAsmHkdfTests, Rfc5869Tc2NoSaltNoInfo) {
    const auto ikm = from_hex<22>("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    const auto expected_okm = from_hex<42>(
        "c8c96e710f89b0d7990bca68bcdec8cf"
        "854062e54c73a7abc743fade9b242daa"
        "cc1cea5670415b52849c");

    auto attrs = ArmAsmBackend::make_hkdf_derive_attrs(ikm.size() * 8U);
    ArmAsmBackend::KeyId id = ArmAsmBackend::null_key_id();
    ASSERT_EQ(ArmAsmBackend::import_key(&attrs, ikm.data(), ikm.size(), &id),
              ArmAsmBackend::ok);

    auto op = ArmAsmBackend::make_kdf_op();
    ASSERT_EQ(ArmAsmBackend::key_derivation_setup(&op, ArmAsmBackend::alg_hkdf()),
              ArmAsmBackend::ok);
    ASSERT_EQ(ArmAsmBackend::key_derivation_input_key(
                  &op, ArmAsmBackend::kdf_step_secret(), id),
              ArmAsmBackend::ok);
    ASSERT_EQ(ArmAsmBackend::key_derivation_input_bytes(
                  &op, ArmAsmBackend::kdf_step_info(), nullptr, 0),
              ArmAsmBackend::ok);

    std::array<uint8_t, 42> okm{};
    ASSERT_EQ(ArmAsmBackend::key_derivation_output_bytes(&op, okm.data(), okm.size()),
              ArmAsmBackend::ok);
    ArmAsmBackend::key_derivation_abort(&op);
    ArmAsmBackend::destroy_key(id);

    for (std::size_t i = 0; i < 42; ++i) {
        EXPECT_EQ(okm[i], expected_okm[i]) << "OKM byte " << i; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    }
}

// SIGMA-style: 80-byte output, info="sigma", no salt, zero IKM.
//   OKM mac_key  = 3d965e...afba (48 bytes)
//   OKM sess_key = 98cf5c...2ec6e (32 bytes)
TEST_F(ArmAsmHkdfTests, SigmaStyleHkdf80Bytes) {
    const std::array<uint8_t, 32> ikm{};  // all zeros
    const std::array<uint8_t, 5>  info = {'s','i','g','m','a'};
    const auto expected_mac  = from_hex<48>(
        "3d965e44429766b7480ee9d3f9afe8d1"
        "32fe043e8fc53746568cf7447f8037cb"
        "473fd20265fb085c9764695f6173afba");
    const auto expected_sess = from_hex<32>(
        "98cf5cbad9907f9ad5ca022fce3f4d32"
        "ecf86cf4c0b7a41bb43b21fbffc2ec6e");

    auto attrs = ArmAsmBackend::make_hkdf_derive_attrs(ikm.size() * 8U);
    ArmAsmBackend::KeyId id = ArmAsmBackend::null_key_id();
    ASSERT_EQ(ArmAsmBackend::import_key(&attrs, ikm.data(), ikm.size(), &id),
              ArmAsmBackend::ok);

    auto op = ArmAsmBackend::make_kdf_op();
    ASSERT_EQ(ArmAsmBackend::key_derivation_setup(&op, ArmAsmBackend::alg_hkdf()),
              ArmAsmBackend::ok);
    ASSERT_EQ(ArmAsmBackend::key_derivation_input_key(
                  &op, ArmAsmBackend::kdf_step_secret(), id),
              ArmAsmBackend::ok);
    ASSERT_EQ(ArmAsmBackend::key_derivation_input_bytes(
                  &op, ArmAsmBackend::kdf_step_info(), info.data(), info.size()),
              ArmAsmBackend::ok);

    std::array<uint8_t, 80> okm{};
    ASSERT_EQ(ArmAsmBackend::key_derivation_output_bytes(&op, okm.data(), okm.size()),
              ArmAsmBackend::ok);
    ArmAsmBackend::key_derivation_abort(&op);
    ArmAsmBackend::destroy_key(id);

    for (std::size_t i = 0; i < 48; ++i) {
        EXPECT_EQ(okm[i], expected_mac[i]) << "mac_key byte " << i; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    }
    for (std::size_t i = 0; i < 32; ++i) {
        EXPECT_EQ(okm[48 + i], expected_sess[i]) << "sess_key byte " << i; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index,cppcoreguidelines-avoid-magic-numbers)
    }
}

// Library-level derive_key_impl<ArmAsmBackend> produces the same OKM.
// Uses 84-byte IKM to satisfy derive_key_impl's IKM >= 2*output_length check.
TEST_F(ArmAsmHkdfTests, LibraryDeriveKeyImplMatchesVector) {
    // IKM = 0x00..0x53 (84 bytes), salt = 0x00..0c (13 bytes), info = 0xf0..f9 (10 bytes)
    const auto ikm_arr  = from_hex<84>(
        "000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f"
        "202122232425262728292a2b2c2d2e2f"
        "303132333435363738393a3b3c3d3e3f"
        "404142434445464748494a4b4c4d4e4f"
        "50515253");
    const std::array<uint8_t, 13> salt_arr = from_hex<13>("000102030405060708090a0b0c");
    const std::array<uint8_t, 10> info_arr = from_hex<10>("f0f1f2f3f4f5f6f7f8f9");
    const auto expected_okm = from_hex<42>(
        "5ee992b955738e79b66b1fad1ad88899"
        "9f945bbc8ac72c54e01842ca994102b3"
        "a0057d0952991f3179c7");

    SecureBuffer ikm(ikm_arr.size());
    std::memcpy(ikm.data(), ikm_arr.data(), ikm_arr.size());
    SecureBuffer salt_buf(salt_arr.size());
    std::memcpy(salt_buf.data(), salt_arr.data(), salt_arr.size());
    SecureBuffer info_buf(info_arr.size());
    std::memcpy(info_buf.data(), info_arr.data(), info_arr.size());

    auto result = derive_key_impl<ArmAsmBackend>(
        42,
        std::optional<SecureBuffer>(std::move(ikm)),
        std::optional<SecureBuffer>(std::move(salt_buf)),
        std::optional<SecureBuffer>(std::move(info_buf)));
    ASSERT_TRUE(result.has_value()) << result.error().message();
    ASSERT_EQ(result->size(), 42U);
    for (std::size_t i = 0; i < 42; ++i) {
        EXPECT_EQ((*result)[i], expected_okm[i]) << "OKM byte " << i; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    }
}

// ---------------------------------------------------------------------------
// Phase 5: key management tests — generate_key and export_key
// ---------------------------------------------------------------------------

class ArmAsmKeyMgmtTests : public ::testing::Test {};

TEST_F(ArmAsmKeyMgmtTests, GenerateAes256GcmKeyAndRoundTrip) {
    // Generate an AES-256-GCM key, encrypt, then decrypt.
    ArmAsmBackend::KeyAttributes attrs = ArmAsmBackend::make_aes256_gcm_encrypt_attrs();
    ArmAsmBackend::KeyId enc_id = ArmAsmBackend::null_key_id();
    ASSERT_EQ(ArmAsmBackend::generate_key(&attrs, &enc_id), ArmAsmBackend::ok);
    EXPECT_NE(enc_id, ArmAsmBackend::null_key_id());

    const std::array<uint8_t, 12> iv = {0x01,0x02,0x03,0x04,0x05,0x06,
                                         0x07,0x08,0x09,0x0a,0x0b,0x0c};
    const std::array<uint8_t, 16> pt = {0x48,0x65,0x6c,0x6c,0x6f,0x2c,
                                         0x20,0x57,0x6f,0x72,0x6c,0x64,
                                         0x21,0x0a,0x00,0x00};
    std::array<uint8_t, 32> ct{};  // 16 + 16 tag
    std::size_t ct_len = 0;

    ASSERT_EQ(ArmAsmBackend::aead_encrypt(
        enc_id, ArmAsmBackend::alg_aes_gcm(),
        iv.data(), iv.size(),
        nullptr, 0,
        pt.data(), pt.size(),
        ct.data(), ct.size(), &ct_len), ArmAsmBackend::ok);
    EXPECT_EQ(ct_len, 32U);

    // Decrypt with the same key.
    std::array<uint8_t, 16> recovered{};
    std::size_t recovered_len = 0;
    ASSERT_EQ(ArmAsmBackend::aead_decrypt(
        enc_id, ArmAsmBackend::alg_aes_gcm(),
        iv.data(), iv.size(),
        nullptr, 0,
        ct.data(), ct_len,
        recovered.data(), recovered.size(), &recovered_len), ArmAsmBackend::ok);
    EXPECT_EQ(recovered_len, pt.size());
    for (std::size_t i = 0; i < pt.size(); ++i) {
        EXPECT_EQ(recovered[i], pt[i]) << "byte " << i; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    }

    ArmAsmBackend::destroy_key(enc_id);
}

TEST_F(ArmAsmKeyMgmtTests, ExportImportedKeyReturnsOriginalBytes) {
    // Import a known key, then export it and verify the bytes match.
    const std::array<uint8_t, 32> original = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
    };
    ArmAsmBackend::KeyAttributes attrs = ArmAsmBackend::make_aes256_gcm_encrypt_attrs();
    ArmAsmBackend::KeyId id = ArmAsmBackend::null_key_id();
    ASSERT_EQ(ArmAsmBackend::import_key(&attrs, original.data(), original.size(), &id),
              ArmAsmBackend::ok);

    std::array<uint8_t, 32> exported{};
    std::size_t exported_len = 0;
    ASSERT_EQ(ArmAsmBackend::export_key(id, exported.data(), exported.size(), &exported_len),
              ArmAsmBackend::ok);
    EXPECT_EQ(exported_len, 32U);
    for (std::size_t i = 0; i < 32; ++i) {
        EXPECT_EQ(exported[i], original[i]) << "byte " << i; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    }

    ArmAsmBackend::destroy_key(id);
}

TEST_F(ArmAsmKeyMgmtTests, ExportGeneratedKeyHasCorrectSize) {
    // A generated AES-256 key must export as exactly 32 bytes.
    ArmAsmBackend::KeyAttributes attrs = ArmAsmBackend::make_aes256_gcm_decrypt_attrs();
    ArmAsmBackend::KeyId id = ArmAsmBackend::null_key_id();
    ASSERT_EQ(ArmAsmBackend::generate_key(&attrs, &id), ArmAsmBackend::ok);

    std::array<uint8_t, 64> buf{};
    std::size_t len = 0;
    ASSERT_EQ(ArmAsmBackend::export_key(id, buf.data(), buf.size(), &len),
              ArmAsmBackend::ok);
    EXPECT_EQ(len, aes256_key_size_bytes);

    ArmAsmBackend::destroy_key(id);
}

TEST_F(ArmAsmKeyMgmtTests, GenerateKeyZeroSizeAttrsReturnsError) {
    ArmAsmBackend::KeyAttributes attrs{};  // key_bytes == 0
    ArmAsmBackend::KeyId id = ArmAsmBackend::null_key_id();
    EXPECT_NE(ArmAsmBackend::generate_key(&attrs, &id), ArmAsmBackend::ok);
    EXPECT_EQ(id, ArmAsmBackend::null_key_id());
}

TEST_F(ArmAsmKeyMgmtTests, GenerateKeyNullAttrsReturnsError) {
    ArmAsmBackend::KeyId id = ArmAsmBackend::null_key_id();
    EXPECT_NE(ArmAsmBackend::generate_key(nullptr, &id), ArmAsmBackend::ok);
}

TEST_F(ArmAsmKeyMgmtTests, ExportKeyBadIdReturnsError) {
    std::array<uint8_t, 32> buf{};
    std::size_t len = 0;
    EXPECT_NE(ArmAsmBackend::export_key(ArmAsmBackend::null_key_id(),
                                         buf.data(), buf.size(), &len),
              ArmAsmBackend::ok);
}

TEST_F(ArmAsmKeyMgmtTests, ExportKeyBufferTooSmallReturnsError) {
    ArmAsmBackend::KeyAttributes attrs = ArmAsmBackend::make_aes256_gcm_encrypt_attrs();
    ArmAsmBackend::KeyId id = ArmAsmBackend::null_key_id();
    ASSERT_EQ(ArmAsmBackend::generate_key(&attrs, &id), ArmAsmBackend::ok);

    std::array<uint8_t, 16> small_buf{};  // too small for 32-byte key
    std::size_t len = 0;
    EXPECT_NE(ArmAsmBackend::export_key(id, small_buf.data(), small_buf.size(), &len),
              ArmAsmBackend::ok);

    ArmAsmBackend::destroy_key(id);
}

#endif  // SAFE_CRYPTO_PROVIDER_ARM_ASM
