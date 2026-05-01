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
    (void)ArmAsmBackend::key_derivation_abort(&op);
    (void)ArmAsmBackend::destroy_key(id);

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
    (void)ArmAsmBackend::key_derivation_abort(&op);
    (void)ArmAsmBackend::destroy_key(id);

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
    (void)ArmAsmBackend::key_derivation_abort(&op);
    (void)ArmAsmBackend::destroy_key(id);

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

    (void)ArmAsmBackend::destroy_key(enc_id);
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

    (void)ArmAsmBackend::destroy_key(id);
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

    (void)ArmAsmBackend::destroy_key(id);
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

    (void)ArmAsmBackend::destroy_key(id);
}

// ---------------------------------------------------------------------------
// P-256 / P-384 dead-code coverage: ct_swap and scalar_from_bytes64/96
//
// p256_ct_swap is defined in p256_point.hpp but not called by the current
// scalar multiplication (which inlines the CT select). Tested here directly.
//
// p256_scalar_from_bytes64 and p384_scalar_from_bytes96 reduce a double-width
// big-endian scalar mod the curve order. They are not called from the ECDSA
// paths (which only need 32/48-byte scalars) but are part of the API.
//
// KAT vectors for from_bytes64/96 (derived from curve order n):
//   P-256: n = ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
//     input = 00..00 ‖ (n+1) → output = 1
//     input = 00..01 ‖ (2n+42 low 256 bits) → output = 42
//   P-384: n = ffffffff...c7634d81f4372ddf581a0db248b0a77aecec196accc52973
//     input = 00..00 ‖ (n+1) → output = 1
// ---------------------------------------------------------------------------

class ArmAsmPointUtilTests : public ::testing::Test {
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

// p256_ct_swap: swap==1 exchanges the two points; swap==0 leaves them unchanged.
TEST_F(ArmAsmPointUtilTests, P256CtSwapExchangesWhenSwapIsOne) {
    using namespace arm_asm::detail;
    const P256Point G{.X = p256_Gx, .Y = p256_Gy, .Z = fe256_one};
    const P256Point identity = p256_identity;
    P256Point a = G;
    P256Point b = identity;

    p256_ct_swap(a, b, 1U);  // swap=1: a↔b

    EXPECT_TRUE(p256_point_is_identity(a));
    for (int i = 0; i < 4; ++i) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        EXPECT_EQ(b.X.v[i], G.X.v[i]); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
        EXPECT_EQ(b.Y.v[i], G.Y.v[i]); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    }
}

TEST_F(ArmAsmPointUtilTests, P256CtSwapNoOpWhenSwapIsZero) {
    using namespace arm_asm::detail;
    const P256Point G{.X = p256_Gx, .Y = p256_Gy, .Z = fe256_one};
    const P256Point identity = p256_identity;
    P256Point a = G;
    P256Point b = identity;

    p256_ct_swap(a, b, 0U);  // swap=0: no change

    for (int i = 0; i < 4; ++i) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        EXPECT_EQ(a.X.v[i], G.X.v[i]); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
        EXPECT_EQ(a.Y.v[i], G.Y.v[i]); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    }
    EXPECT_TRUE(p256_point_is_identity(b));
}

// p256_scalar_from_bytes64: 512-bit big-endian value reduced mod n.
// TV1: input = 0^32 ‖ (n+1)  →  1
TEST_F(ArmAsmPointUtilTests, P256ScalarFromBytes64NPlus1ReturnsOne) {
    using namespace arm_asm::detail;
    const auto input = from_hex<64>(
        "0000000000000000000000000000000000000000000000000000000000000000"
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552");
    const Fe256 result = p256_scalar_from_bytes64(input.data());
    EXPECT_EQ(result.v[0], 1U); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    for (int i = 1; i < 4; ++i) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        EXPECT_EQ(result.v[i], 0U); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    }
}

// TV2: input = 0^32 ‖ (n+42)  →  42
// (n+42 as the low 256 bits; high 256 bits are zero)
TEST_F(ArmAsmPointUtilTests, P256ScalarFromBytes64NPlus42Returns42) {
    using namespace arm_asm::detail;
    const auto input = from_hex<64>(
        "0000000000000000000000000000000000000000000000000000000000000000"
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63257b");
    const Fe256 result = p256_scalar_from_bytes64(input.data());
    EXPECT_EQ(result.v[0], 42U); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    for (int i = 1; i < 4; ++i) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        EXPECT_EQ(result.v[i], 0U); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    }
}

// p384_scalar_from_bytes96: 768-bit big-endian value reduced mod P-384 n.
// TV1: input = 0^48 ‖ (n+1)  →  1
// (n+1 occupies exactly 48 bytes; high 48 bytes are zero)
TEST_F(ArmAsmPointUtilTests, P384ScalarFromBytes96NPlus1ReturnsOne) {
    using namespace arm_asm::detail;
    const auto input = from_hex<96>(
        "000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000"
        "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf"
        "581a0db248b0a77aecec196accc52974");
    const Fe384 result = p384_scalar_from_bytes96(input.data());
    EXPECT_EQ(result.v[0], 1U); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    for (int i = 1; i < 6; ++i) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        EXPECT_EQ(result.v[i], 0U); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    }
}

// ---------------------------------------------------------------------------
// Phase 7: ChaCha20-Poly1305 tests (RFC 8439)
// ---------------------------------------------------------------------------

class ArmAsmChaCha20Poly1305Tests : public ::testing::Test {
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

// RFC 8439 §2.8.2 AEAD construction test vector.
//   Key   : 808182...9f (32 bytes)
//   Nonce : 07000000 4041424344454647 (12 bytes)
//   AAD   : 50515253c0c1c2c3c4c5c6c7 (12 bytes)
//   PT    : "Ladies and Gentlemen of the class of '99: ..." (114 bytes)
//   CT    : d31a8d34...64b6116 (114 bytes)
//   Tag   : 1ae10b594f09e26a7e902ecbd0600691
TEST_F(ArmAsmChaCha20Poly1305Tests, Rfc8439Section282EncryptWithAad) {
    const auto key   = from_hex<32>("808182838485868788898a8b8c8d8e8f"
                                    "909192939495969798999a9b9c9d9e9f");
    const auto nonce = from_hex<12>("070000004041424344454647");
    const auto aad   = from_hex<12>("50515253c0c1c2c3c4c5c6c7");

    const char* pt_str =
        "4c616469657320616e642047656e746c"
        "656d656e206f662074686520636c6173"
        "73206f6620273939"
        "3a20496620492063"
        "6f756c64206f6666"
        "657220796f75206f"
        "6e6c79206f6e6520"
        "74697020666f7220"
        "74686520667574757265"
        "2c2073756e73637265656e"
        "20776f756c6420626520"
        "69742e";
    const auto pt = from_hex<114>(
        "4c616469657320616e642047656e746c"
        "656d656e206f662074686520636c6173"
        "73206f6620273939"
        "3a20496620492063"
        "6f756c64206f6666"
        "657220796f75206f"
        "6e6c79206f6e6520"
        "74697020666f7220"
        "74686520667574757265"
        "2c2073756e73637265656e"
        "20776f756c6420626520"
        "69742e");
    (void)pt_str;

    const auto expected_ct = from_hex<114>(
        "d31a8d34648e60db7b86afbc53ef7ec2"
        "a4aded51296e08fea9e2b5a736ee62d6"
        "3dbea45e8ca96712"
        "82fafb69da92728b"
        "1a71de0a9e060b29"
        "05d6a5b67ecd3b36"
        "92ddbd7f2d778b8c"
        "9803aee328091b58"
        "fab324e4fad675945585808b"
        "4831d7bc3ff4def08e4b7a9d"
        "e576d26586cec64b"
        "6116");
    const auto expected_tag = from_hex<16>("1ae10b594f09e26a7e902ecbd0600691");

    // Import key.
    auto attrs = ArmAsmBackend::make_chacha20_poly1305_encrypt_attrs();
    ArmAsmBackend::KeyId id = ArmAsmBackend::null_key_id();
    ASSERT_EQ(ArmAsmBackend::import_key(&attrs, key.data(), key.size(), &id),
              ArmAsmBackend::ok);

    std::array<uint8_t, 114 + 16> out{};
    std::size_t out_len = 0;
    ASSERT_EQ(ArmAsmBackend::aead_encrypt(
                  id, ArmAsmBackend::alg_chacha20_poly1305(),
                  nonce.data(), nonce.size(),
                  aad.data(), aad.size(),
                  pt.data(), pt.size(),
                  out.data(), out.size(), &out_len),
              ArmAsmBackend::ok);
    ASSERT_EQ(out_len, 114U + 16U);

    for (std::size_t i = 0; i < 114; ++i) {
        EXPECT_EQ(out[i], expected_ct[i]) << "ct byte " << i; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    }
    for (std::size_t i = 0; i < 16; ++i) {
        EXPECT_EQ(out[114 + i], expected_tag[i]) << "tag byte " << i; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index,cppcoreguidelines-avoid-magic-numbers)
    }
    (void)ArmAsmBackend::destroy_key(id);
}

// RFC 8439 §2.8.2 decrypt: feed ct‖tag back through aead_decrypt.
TEST_F(ArmAsmChaCha20Poly1305Tests, Rfc8439Section282DecryptWithAad) {
    const auto key   = from_hex<32>("808182838485868788898a8b8c8d8e8f"
                                    "909192939495969798999a9b9c9d9e9f");
    const auto nonce = from_hex<12>("070000004041424344454647");
    const auto aad   = from_hex<12>("50515253c0c1c2c3c4c5c6c7");

    const auto expected_pt = from_hex<114>(
        "4c616469657320616e642047656e746c"
        "656d656e206f662074686520636c6173"
        "73206f6620273939"
        "3a20496620492063"
        "6f756c64206f6666"
        "657220796f75206f"
        "6e6c79206f6e6520"
        "74697020666f7220"
        "74686520667574757265"
        "2c2073756e73637265656e"
        "20776f756c6420626520"
        "69742e");

    // Build ct‖tag.
    const auto ct = from_hex<114>(
        "d31a8d34648e60db7b86afbc53ef7ec2"
        "a4aded51296e08fea9e2b5a736ee62d6"
        "3dbea45e8ca96712"
        "82fafb69da92728b"
        "1a71de0a9e060b29"
        "05d6a5b67ecd3b36"
        "92ddbd7f2d778b8c"
        "9803aee328091b58"
        "fab324e4fad675945585808b"
        "4831d7bc3ff4def08e4b7a9d"
        "e576d26586cec64b"
        "6116");
    const auto tag = from_hex<16>("1ae10b594f09e26a7e902ecbd0600691");
    std::array<uint8_t, 114 + 16> ct_tag{};
    std::memcpy(ct_tag.data(), ct.data(), 114); // NOLINT(cppcoreguidelines-avoid-magic-numbers)
    std::memcpy(ct_tag.data() + 114, tag.data(), 16); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic,cppcoreguidelines-avoid-magic-numbers)

    auto attrs = ArmAsmBackend::make_chacha20_poly1305_decrypt_attrs();
    ArmAsmBackend::KeyId id = ArmAsmBackend::null_key_id();
    ASSERT_EQ(ArmAsmBackend::import_key(&attrs, key.data(), key.size(), &id),
              ArmAsmBackend::ok);

    std::array<uint8_t, 114> pt{};
    std::size_t pt_len = 0;
    ASSERT_EQ(ArmAsmBackend::aead_decrypt(
                  id, ArmAsmBackend::alg_chacha20_poly1305(),
                  nonce.data(), nonce.size(),
                  aad.data(), aad.size(),
                  ct_tag.data(), ct_tag.size(),
                  pt.data(), pt.size(), &pt_len),
              ArmAsmBackend::ok);
    ASSERT_EQ(pt_len, 114U);

    for (std::size_t i = 0; i < 114; ++i) {
        EXPECT_EQ(pt[i], expected_pt[i]) << "pt byte " << i; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    }
    (void)ArmAsmBackend::destroy_key(id);
}

// Short KAT: 16-byte PT, 4-byte AAD, key=0x00..1f, nonce=0x00..0b.
//   CT  : 89fa0a032d12a347bf8a35f89410006c
//   Tag : 26ca05862a111ecd36a2289af1dc1140
TEST_F(ArmAsmChaCha20Poly1305Tests, ShortVectorRoundTrip) {
    const auto key   = from_hex<32>("000102030405060708090a0b0c0d0e0f"
                                    "101112131415161718191a1b1c1d1e1f");
    const auto nonce = from_hex<12>("000102030405060708090a0b");
    const auto aad   = from_hex<4>("deadbeef");
    const auto pt    = from_hex<16>("000102030405060708090a0b0c0d0e0f");
    const auto expected_ct  = from_hex<16>("89fa0a032d12a347bf8a35f89410006c");
    const auto expected_tag = from_hex<16>("26ca05862a111ecd36a2289af1dc1140");

    auto attrs = ArmAsmBackend::make_chacha20_poly1305_encrypt_attrs();
    ArmAsmBackend::KeyId id = ArmAsmBackend::null_key_id();
    ASSERT_EQ(ArmAsmBackend::import_key(&attrs, key.data(), key.size(), &id),
              ArmAsmBackend::ok);

    // Encrypt.
    std::array<uint8_t, 32> out{};  // 16 + 16
    std::size_t out_len = 0;
    ASSERT_EQ(ArmAsmBackend::aead_encrypt(
                  id, ArmAsmBackend::alg_chacha20_poly1305(),
                  nonce.data(), nonce.size(),
                  aad.data(), aad.size(),
                  pt.data(), pt.size(),
                  out.data(), out.size(), &out_len),
              ArmAsmBackend::ok);
    ASSERT_EQ(out_len, 32U);
    for (std::size_t i = 0; i < 16; ++i) {
        EXPECT_EQ(out[i], expected_ct[i]) << "ct byte " << i; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    }
    for (std::size_t i = 0; i < 16; ++i) {
        EXPECT_EQ(out[16 + i], expected_tag[i]) << "tag byte " << i; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index,cppcoreguidelines-avoid-magic-numbers)
    }

    // Decrypt.
    std::array<uint8_t, 16> recovered{};
    std::size_t recovered_len = 0;
    ASSERT_EQ(ArmAsmBackend::aead_decrypt(
                  id, ArmAsmBackend::alg_chacha20_poly1305(),
                  nonce.data(), nonce.size(),
                  aad.data(), aad.size(),
                  out.data(), out_len,
                  recovered.data(), recovered.size(), &recovered_len),
              ArmAsmBackend::ok);
    ASSERT_EQ(recovered_len, 16U);
    for (std::size_t i = 0; i < 16; ++i) {
        EXPECT_EQ(recovered[i], pt[i]) << "pt byte " << i; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    }
    (void)ArmAsmBackend::destroy_key(id);
}

// Tampered tag must be rejected and output zeroized.
TEST_F(ArmAsmChaCha20Poly1305Tests, TamperedTagRejected) {
    const auto key   = from_hex<32>("000102030405060708090a0b0c0d0e0f"
                                    "101112131415161718191a1b1c1d1e1f");
    const auto nonce = from_hex<12>("000102030405060708090a0b");
    const auto pt    = from_hex<16>("000102030405060708090a0b0c0d0e0f");

    auto attrs = ArmAsmBackend::make_chacha20_poly1305_encrypt_attrs();
    ArmAsmBackend::KeyId id = ArmAsmBackend::null_key_id();
    ASSERT_EQ(ArmAsmBackend::import_key(&attrs, key.data(), key.size(), &id),
              ArmAsmBackend::ok);

    std::array<uint8_t, 32> ct_tag{};
    std::size_t ct_len = 0;
    ASSERT_EQ(ArmAsmBackend::aead_encrypt(
                  id, ArmAsmBackend::alg_chacha20_poly1305(),
                  nonce.data(), nonce.size(),
                  nullptr, 0,
                  pt.data(), pt.size(),
                  ct_tag.data(), ct_tag.size(), &ct_len),
              ArmAsmBackend::ok);

    ct_tag[0] ^= 0xFFU;  // tamper first ciphertext byte

    std::array<uint8_t, 16> out{};
    std::size_t out_len = 0;
    EXPECT_NE(ArmAsmBackend::aead_decrypt(
                  id, ArmAsmBackend::alg_chacha20_poly1305(),
                  nonce.data(), nonce.size(),
                  nullptr, 0,
                  ct_tag.data(), ct_len,
                  out.data(), out.size(), &out_len),
              ArmAsmBackend::ok);
    for (std::size_t i = 0; i < 16; ++i) {
        EXPECT_EQ(out[i], 0) << "output not zeroized at byte " << i; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    }
    (void)ArmAsmBackend::destroy_key(id);
}

// ---------------------------------------------------------------------------
// SHA3 / HMAC-SHA3 known-answer tests
//
// SHA3 vectors from NIST FIPS 202 and PyCryptodome (verified independently):
//   sha3_256("")    = a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
//   sha3_256("abc") = 3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532
//   sha3_256(0x00..0xc7, 200B) = 5f728f63bf5ee48c77f453c0490398fa645b8d4c4e56be9a41cfec344d6ca899
//   sha3_384("")    = 0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2a
//                     c3713831264adb47fb6bd1e058d5f004
//   sha3_384("abc") = ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b2
//                     98d88cea927ac7f539f1edf228376d25
//   sha3_512("")    = a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6
//                     15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26
//   sha3_512("abc") = b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712da
//                     dfb2701affd5ed6f17f21f9b09bfa84bb39d95c8e5fc168b (trunc 64B)
//   HMAC-SHA3-256(key=0x00..1f, "abc") =
//     632f618ac17ba24355d9ee1fd187cf75bb5b68e6948804bf6674bf5ee7f1c345 (NIST CAVP)
//   HMAC-SHA3-384(key=0x00..1f, "abc") =
//     c3247d777589c8bc4527184299a59598ad32d7f782f6518dac939d717719aa74
//     442f6f4b596f469aab912b1f0ff2e70c
//   HMAC-SHA3-512(key=0x00..1f, "abc") =
//     833b31e777d6b33d7523a579cc3beb276fd6525754c4c54b2d5a347d36240791
//     7a3c626e7edb8e493b42c8e5a696d5e66ba7ad2000eb6cff76cb1ec030130e81
// ---------------------------------------------------------------------------

#include "sha3.hpp"

class ArmAsmSha3Tests : public ::testing::Test {
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

TEST_F(ArmAsmSha3Tests, Sha3_256EmptyMessage) {
    const auto expected = from_hex<32>(
        "a7ffc6f8bf1ed76651c14756a061d662"
        "f580ff4de43b49fa82d80a4b80f8434a");
    std::array<uint8_t, 32> out{};
    arm_asm::detail::sha3_256(nullptr, 0, out.data());
    for (std::size_t i = 0; i < 32; ++i) {
        EXPECT_EQ(out[i], expected[i]) << "byte " << i; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    }
}

TEST_F(ArmAsmSha3Tests, Sha3_256AbcMessage) {
    const auto expected = from_hex<32>(
        "3a985da74fe225b2045c172d6bd390bd"
        "855f086e3e9d525b46bfe24511431532");
    const std::array<uint8_t, 3> msg = { 0x61, 0x62, 0x63 };
    std::array<uint8_t, 32> out{};
    arm_asm::detail::sha3_256(msg.data(), msg.size(), out.data());
    for (std::size_t i = 0; i < 32; ++i) {
        EXPECT_EQ(out[i], expected[i]) << "byte " << i; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    }
}

TEST_F(ArmAsmSha3Tests, Sha3_256MultiBlockMessage) {
    // 200-byte message: 0x00, 0x01, ..., 0xc7
    std::array<uint8_t, 200> msg{}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    for (std::size_t i = 0; i < 200; ++i) { msg[i] = static_cast<uint8_t>(i); } // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers,cppcoreguidelines-pro-bounds-constant-array-index)
    const auto expected = from_hex<32>(
        "5f728f63bf5ee48c77f453c0490398fa"
        "645b8d4c4e56be9a41cfec344d6ca899");
    std::array<uint8_t, 32> out{};
    arm_asm::detail::sha3_256(msg.data(), msg.size(), out.data());
    for (std::size_t i = 0; i < 32; ++i) {
        EXPECT_EQ(out[i], expected[i]) << "byte " << i; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    }
}

TEST_F(ArmAsmSha3Tests, Sha3_384EmptyMessage) {
    const auto expected = from_hex<48>(
        "0c63a75b845e4f7d01107d852e4c2485"
        "c51a50aaaa94fc61995e71bbee983a2a"
        "c3713831264adb47fb6bd1e058d5f004");
    std::array<uint8_t, 48> out{};
    arm_asm::detail::sha3_384(nullptr, 0, out.data());
    for (std::size_t i = 0; i < 48; ++i) {
        EXPECT_EQ(out[i], expected[i]) << "byte " << i; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    }
}

TEST_F(ArmAsmSha3Tests, Sha3_384AbcMessage) {
    const auto expected = from_hex<48>(
        "ec01498288516fc926459f58e2c6ad8d"
        "f9b473cb0fc08c2596da7cf0e49be4b2"
        "98d88cea927ac7f539f1edf228376d25");
    const std::array<uint8_t, 3> msg = { 0x61, 0x62, 0x63 };
    std::array<uint8_t, 48> out{};
    arm_asm::detail::sha3_384(msg.data(), msg.size(), out.data());
    for (std::size_t i = 0; i < 48; ++i) {
        EXPECT_EQ(out[i], expected[i]) << "byte " << i; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    }
}

TEST_F(ArmAsmSha3Tests, Sha3_512EmptyMessage) {
    const auto expected = from_hex<64>(
        "a69f73cca23a9ac5c8b567dc185a756e"
        "97c982164fe25859e0d1dcc1475c80a6"
        "15b2123af1f5f94c11e3e9402c3ac558"
        "f500199d95b6d3e301758586281dcd26");
    std::array<uint8_t, 64> out{};
    arm_asm::detail::sha3_512(nullptr, 0, out.data());
    for (std::size_t i = 0; i < 64; ++i) {
        EXPECT_EQ(out[i], expected[i]) << "byte " << i; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    }
}

TEST_F(ArmAsmSha3Tests, Sha3_512AbcMessage) {
    const auto expected = from_hex<64>(
        "b751850b1a57168a5693cd924b6b096e"
        "08f621827444f70d884f5d0240d2712e"
        "10e116e9192af3c91a7ec57647e39340"
        "57340b4cf408d5a56592f8274eec53f0");
    const std::array<uint8_t, 3> msg = { 0x61, 0x62, 0x63 };
    std::array<uint8_t, 64> out{};
    arm_asm::detail::sha3_512(msg.data(), msg.size(), out.data());
    for (std::size_t i = 0; i < 64; ++i) {
        EXPECT_EQ(out[i], expected[i]) << "byte " << i; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    }
}

// HMAC-SHA3 tests: key = 0x00..0x1f (32 bytes), message = "abc"

TEST_F(ArmAsmSha3Tests, HmacSha3_256AbcMessage) {
    std::array<uint8_t, 32> key{};
    for (std::size_t i = 0; i < 32; ++i) { key[i] = static_cast<uint8_t>(i); } // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    const std::array<uint8_t, 3> msg = { 0x61, 0x62, 0x63 };
    const auto expected = from_hex<32>(
        "632f618ac17ba24355d9ee1fd187cf75"
        "bb5b68e6948804bf6674bf5ee7f1c345");
    std::array<uint8_t, 32> out{};
    arm_asm::detail::hmac_sha3_256(key.data(), key.size(), msg.data(), msg.size(), out.data());
    for (std::size_t i = 0; i < 32; ++i) {
        EXPECT_EQ(out[i], expected[i]) << "byte " << i; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    }
}

TEST_F(ArmAsmSha3Tests, HmacSha3_384AbcMessage) {
    std::array<uint8_t, 32> key{};
    for (std::size_t i = 0; i < 32; ++i) { key[i] = static_cast<uint8_t>(i); } // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    const std::array<uint8_t, 3> msg = { 0x61, 0x62, 0x63 };
    const auto expected = from_hex<48>(
        "c3247d777589c8bc4527184299a59598"
        "ad32d7f782f6518dac939d717719aa74"
        "442f6f4b596f469aab912b1f0ff2e70c");
    std::array<uint8_t, 48> out{};
    arm_asm::detail::hmac_sha3_384(key.data(), key.size(), msg.data(), msg.size(), out.data());
    for (std::size_t i = 0; i < 48; ++i) {
        EXPECT_EQ(out[i], expected[i]) << "byte " << i; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    }
}

TEST_F(ArmAsmSha3Tests, HmacSha3_512AbcMessage) {
    std::array<uint8_t, 32> key{};
    for (std::size_t i = 0; i < 32; ++i) { key[i] = static_cast<uint8_t>(i); } // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    const std::array<uint8_t, 3> msg = { 0x61, 0x62, 0x63 };
    const auto expected = from_hex<64>(
        "833b31e777d6b33d7523a579cc3beb27"
        "6fd6525754c4c54b2d5a347d36240791"
        "7a3c626e7edb8e493b42c8e5a696d5e6"
        "6ba7ad2000eb6cff76cb1ec030130e81");
    std::array<uint8_t, 64> out{};
    arm_asm::detail::hmac_sha3_512(key.data(), key.size(), msg.data(), msg.size(), out.data());
    for (std::size_t i = 0; i < 64; ++i) {
        EXPECT_EQ(out[i], expected[i]) << "byte " << i; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    }
}

// ---------------------------------------------------------------------------
// Poly1305 MAC known-answer tests
//
// Vectors:
//   RFC 8439 §A.3 TV1: 64-byte zero message, all-zero key → all-zero tag
//   RFC 8439 §A.3 TV2: 362-byte IETF submission text
//     key = 0000..00 ‖ 36e5f6b5c5e06070f0efca96227a863e
//     tag = 36e5f6b5c5e06070f0efca96227a863e
//   Custom 96-byte (0x61×96): key=0x00..1f
//     tag = 408aafac65bf6f37cb4d6d69d74dc0f5
//   Custom 128-byte (0x61×128): key=0x00..1f
//     tag = daa0437b0935d2b67bdc3a28e90078a8
//
// TV1 exercises the 4-block path with a trivially zero result.
// TV2 exercises multiple full quad-block iterations (362 / 64 = 5 passes).
// Custom 96B exercises quad-block (64B) + pair (32B).
// Custom 128B exercises exactly two quad-block passes.
// ---------------------------------------------------------------------------

#include "poly1305.hpp"

class ArmAsmPoly1305Tests : public ::testing::Test {
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

// RFC 8439 §A.3 TV1: 64-byte all-zero message, all-zero key → all-zero tag.
// Exercises the 4-block (64B) primary loop path.
TEST_F(ArmAsmPoly1305Tests, Rfc8439Tv1ZeroMessageZeroKey) {
    const std::array<uint8_t, 32> key{};
    const std::array<uint8_t, 64> msg{};
    std::array<uint8_t, 16> tag{};
    arm_asm::detail::poly1305_mac(key.data(), msg.data(), msg.size(), tag.data());
    for (std::size_t i = 0; i < 16; ++i) {
        EXPECT_EQ(tag[i], 0U) << "byte " << i; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    }
}

// RFC 8439 §A.3 TV2: 362-byte IETF text message.
// Exercises multiple consecutive quad-block iterations of poly1305_mac.
TEST_F(ArmAsmPoly1305Tests, Rfc8439Tv2IetfText) {
    const auto key = from_hex<32>(
        "0000000000000000000000000000000036e5f6b5c5e06070f0efca96227a863e");
    const auto expected = from_hex<16>("36e5f6b5c5e06070f0efca96227a863e");

    // RFC 8439 §A.3 TV2 message: 362 bytes.
    const char msg_raw[] =
        "Any submission to the IETF intended by the Contributor for publication"
        " as all or part of an IETF Internet-Draft or RFC and any statement mad"
        "e within the context of an IETF activity is considered an \"IETF Contr"
        "ibution\". Such statements include oral statements in IETF sessions, as"
        " well as written and electronic communications made at any time or plac"
        "e, which are addressed to";
    const std::size_t msg_len = sizeof(msg_raw) - 1; // exclude null terminator

    std::array<uint8_t, 16> tag{};
    arm_asm::detail::poly1305_mac(
        key.data(),
        reinterpret_cast<const uint8_t*>(msg_raw), // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        msg_len, tag.data());
    for (std::size_t i = 0; i < 16; ++i) {
        EXPECT_EQ(tag[i], expected[i]) << "byte " << i; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    }
}

// Custom 96-byte message (0x61 × 96), key = 0x00..0x1f.
// Exercises quad-block (64B) path then pair (32B) path.
TEST_F(ArmAsmPoly1305Tests, Custom96ByteMessage) {
    std::array<uint8_t, 32> key{};
    for (std::size_t i = 0; i < 32; ++i) { key[i] = static_cast<uint8_t>(i); } // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    std::array<uint8_t, 96> msg{};
    std::fill(msg.begin(), msg.end(), 0x61U);
    const auto expected = from_hex<16>("408aafac65bf6f37cb4d6d69d74dc0f5");

    std::array<uint8_t, 16> tag{};
    arm_asm::detail::poly1305_mac(key.data(), msg.data(), msg.size(), tag.data());
    for (std::size_t i = 0; i < 16; ++i) {
        EXPECT_EQ(tag[i], expected[i]) << "byte " << i; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    }
}

// Custom 128-byte message (0x61 × 128), key = 0x00..0x1f.
// Exercises exactly two consecutive quad-block iterations.
TEST_F(ArmAsmPoly1305Tests, Custom128ByteMessage) {
    std::array<uint8_t, 32> key{};
    for (std::size_t i = 0; i < 32; ++i) { key[i] = static_cast<uint8_t>(i); } // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    std::array<uint8_t, 128> msg{};
    std::fill(msg.begin(), msg.end(), 0x61U);
    const auto expected = from_hex<16>("daa0437b0935d2b67bdc3a28e90078a8");

    std::array<uint8_t, 16> tag{};
    arm_asm::detail::poly1305_mac(key.data(), msg.data(), msg.size(), tag.data());
    for (std::size_t i = 0; i < 16; ++i) {
        EXPECT_EQ(tag[i], expected[i]) << "byte " << i; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    }
}

// SHA3 dispatch via ArmAsmBackend::hash_compute
TEST_F(ArmAsmSha3Tests, BackendSha3_256Dispatch) {
    const auto expected = from_hex<32>(
        "3a985da74fe225b2045c172d6bd390bd"
        "855f086e3e9d525b46bfe24511431532");
    const std::array<uint8_t, 3> msg = { 0x61, 0x62, 0x63 };
    std::array<uint8_t, 32> out{};
    std::size_t out_len = 0;
    ASSERT_EQ(ArmAsmBackend::hash_compute(
                  ArmAsmBackend::alg_sha(ShaVariant::Sha3_256),
                  msg.data(), msg.size(),
                  out.data(), out.size(), &out_len),
              ArmAsmBackend::ok);
    ASSERT_EQ(out_len, 32U);
    for (std::size_t i = 0; i < 32; ++i) {
        EXPECT_EQ(out[i], expected[i]) << "byte " << i; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    }
}

#endif  // SAFE_CRYPTO_PROVIDER_ARM_ASM
