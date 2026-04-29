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
