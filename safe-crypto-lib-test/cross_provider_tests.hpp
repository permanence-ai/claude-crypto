/*
Copyright Permanence AI, 2026. All rights reserved.

*/

#pragma once

// Cross-provider parity tests: ARM ASM vs PSA/MbedTLS.
//
// Each test generates a random input, runs the same operation through both
// ArmAsmBackend and RealPsaBackend, and asserts byte-for-byte identical
// output.  This catches implementation drift that KAT tests cannot find —
// a wrong implementation can still pass a KAT if the reference vector was
// derived from the same wrong code.
//
// Operations covered:
//   SHA-256, SHA-384, SHA-512
//   SHA3-256, SHA3-384, SHA3-512
//   HMAC-SHA-256, HMAC-SHA-384, HMAC-SHA-512
//   HMAC-SHA3-256, HMAC-SHA3-384, HMAC-SHA3-512
//   AES-256-GCM encrypt+decrypt (same key+nonce fed to both)
//   ChaCha20-Poly1305 encrypt+decrypt (same key+nonce fed to both)
//   HKDF-SHA-384 (same IKM, salt, info fed to both)
//
// The file is always compiled but the tests are guarded by
// SAFE_CRYPTO_PROVIDER_ARM_ASM (the test binary links both provider
// libraries regardless of the active provider, but only runs these tests
// when the ARM ASM symbols are available).

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>

#include <gtest/gtest.h>

// Library headers must precede provider headers (same ordering as bench_main).
#include "defs.hpp"
#include "sha_variant.hpp"
#include "secure_buffer.hpp"

#include "arm_asm_backend.hpp"
#include "psa_mbedtls_backend.hpp"

#include "aead.hpp"
#include "digests.hpp"
#include "kdf.hpp"
#include "mac.hpp"

#include "test_utils.hpp"

#ifdef SAFE_CRYPTO_PROVIDER_ARM_ASM


// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Fill a raw byte array with a deterministic pattern seeded from index.
template<std::size_t N>
static std::array<uint8_t, N> make_test_bytes(uint8_t seed = 0) {
    std::array<uint8_t, N> out{};
    for (std::size_t i = 0; i < N; ++i) {
        out[i] = static_cast<uint8_t>((i ^ seed) & 0xFFU); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    }
    return out;
}

// Compare two fixed-size output buffers and report the first differing byte.
template<std::size_t N>
static void expect_equal_outputs(const std::array<uint8_t, N>& psa,
                                  const std::array<uint8_t, N>& arm,
                                  const char* label)
{
    for (std::size_t i = 0; i < N; ++i) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
        EXPECT_EQ(psa[i], arm[i]) << label << ": first mismatch at byte " << i;
        if (psa[i] != arm[i]) { return; } // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    }
}


// ---------------------------------------------------------------------------
// Base fixture: initialises PSA before each test.
// ---------------------------------------------------------------------------

class CrossProviderTest : public ::testing::Test {
protected:
    void SetUp() override {
        ASSERT_EQ(RealPsaBackend::crypto_init(), RealPsaBackend::ok)
            << "psa_crypto_init() failed";
    }
};


// ---------------------------------------------------------------------------
// Hash parity
// ---------------------------------------------------------------------------

class CrossProviderHashTests : public CrossProviderTest {};

// Parameterised by SHA variant — one test body covers all six variants.
template<ShaVariant V>
static void run_hash_parity_test(const char* label) {
    // Three message sizes: empty, one block, multi-block.
    for (std::size_t msg_len : {std::size_t{0}, std::size_t{64}, std::size_t{200}}) {
        const auto msg = make_random_secure_buffer(msg_len);

        constexpr std::size_t out_size = sha_output_size(V);
        std::array<uint8_t, out_size> psa_out{};
        std::array<uint8_t, out_size> arm_out{};
        std::size_t psa_len = 0, arm_len = 0;

        ASSERT_EQ(RealPsaBackend::hash_compute(
            RealPsaBackend::alg_sha(V), msg.data(), msg.size(),
            psa_out.data(), psa_out.size(), &psa_len), RealPsaBackend::ok)
            << label << " PSA hash_compute failed (msg_len=" << msg_len << ")";

        ASSERT_EQ(ArmAsmBackend::hash_compute(
            ArmAsmBackend::alg_sha(V), msg.data(), msg.size(),
            arm_out.data(), arm_out.size(), &arm_len), ArmAsmBackend::ok)
            << label << " ARM hash_compute failed (msg_len=" << msg_len << ")";

        ASSERT_EQ(psa_len, arm_len) << label << " output length mismatch";
        expect_equal_outputs(psa_out, arm_out, label);
    }
}

TEST_F(CrossProviderHashTests, Sha256Parity)  { run_hash_parity_test<ShaVariant::Sha256> ("SHA-256"); }
TEST_F(CrossProviderHashTests, Sha384Parity)  { run_hash_parity_test<ShaVariant::Sha384> ("SHA-384"); }
TEST_F(CrossProviderHashTests, Sha512Parity)  { run_hash_parity_test<ShaVariant::Sha512> ("SHA-512"); }
TEST_F(CrossProviderHashTests, Sha3_256Parity){ run_hash_parity_test<ShaVariant::Sha3_256>("SHA3-256"); }
TEST_F(CrossProviderHashTests, Sha3_384Parity){ run_hash_parity_test<ShaVariant::Sha3_384>("SHA3-384"); }
TEST_F(CrossProviderHashTests, Sha3_512Parity){ run_hash_parity_test<ShaVariant::Sha3_512>("SHA3-512"); }


// ---------------------------------------------------------------------------
// HMAC parity
// ---------------------------------------------------------------------------

class CrossProviderHmacTests : public CrossProviderTest {};

template<ShaVariant V>
static void run_hmac_parity_test(const char* label) {
    const auto key = make_random_secure_buffer(48); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    const auto msg = make_random_secure_buffer(128); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)

    constexpr std::size_t out_size = sha_output_size(V);
    std::array<uint8_t, out_size> psa_out{};
    std::array<uint8_t, out_size> arm_out{};
    std::size_t psa_len = 0, arm_len = 0;

    // Import key into PSA store.
    auto psa_attrs = RealPsaBackend::make_hmac_generate_attrs(V, key.size() * 8U); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    RealPsaBackend::KeyId psa_id = RealPsaBackend::null_key_id();
    ASSERT_EQ(RealPsaBackend::import_key(&psa_attrs, key.data(), key.size(), &psa_id),
              RealPsaBackend::ok) << label << " PSA key import failed";

    ASSERT_EQ(RealPsaBackend::mac_compute(
        psa_id, RealPsaBackend::alg_hmac(V),
        msg.data(), msg.size(),
        psa_out.data(), psa_out.size(), &psa_len), RealPsaBackend::ok)
        << label << " PSA mac_compute failed";
    RealPsaBackend::destroy_key(psa_id);

    // Import key into ARM ASM store.
    auto arm_attrs = ArmAsmBackend::make_hmac_generate_attrs(V, key.size() * 8U); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ArmAsmBackend::KeyId arm_id = ArmAsmBackend::null_key_id();
    ASSERT_EQ(ArmAsmBackend::import_key(&arm_attrs, key.data(), key.size(), &arm_id),
              ArmAsmBackend::ok) << label << " ARM key import failed";

    ASSERT_EQ(ArmAsmBackend::mac_compute(
        arm_id, ArmAsmBackend::alg_hmac(V),
        msg.data(), msg.size(),
        arm_out.data(), arm_out.size(), &arm_len), ArmAsmBackend::ok)
        << label << " ARM mac_compute failed";
    ArmAsmBackend::destroy_key(arm_id);

    ASSERT_EQ(psa_len, arm_len) << label << " output length mismatch";
    expect_equal_outputs(psa_out, arm_out, label);
}

TEST_F(CrossProviderHmacTests, HmacSha256Parity)   { run_hmac_parity_test<ShaVariant::Sha256> ("HMAC-SHA-256"); }
TEST_F(CrossProviderHmacTests, HmacSha384Parity)   { run_hmac_parity_test<ShaVariant::Sha384> ("HMAC-SHA-384"); }
TEST_F(CrossProviderHmacTests, HmacSha512Parity)   { run_hmac_parity_test<ShaVariant::Sha512> ("HMAC-SHA-512"); }
TEST_F(CrossProviderHmacTests, HmacSha3_256Parity) { run_hmac_parity_test<ShaVariant::Sha3_256>("HMAC-SHA3-256"); }
TEST_F(CrossProviderHmacTests, HmacSha3_384Parity) { run_hmac_parity_test<ShaVariant::Sha3_384>("HMAC-SHA3-384"); }
TEST_F(CrossProviderHmacTests, HmacSha3_512Parity) { run_hmac_parity_test<ShaVariant::Sha3_512>("HMAC-SHA3-512"); }


// ---------------------------------------------------------------------------
// AES-256-GCM parity
// ---------------------------------------------------------------------------

class CrossProviderAesGcmTests : public CrossProviderTest {};

TEST_F(CrossProviderAesGcmTests, EncryptParity) {
    const auto key     = make_test_bytes<32>(0xA0U);
    const auto nonce   = make_test_bytes<12>(0xB0U);
    const auto aad     = make_test_bytes<20>(0xC0U); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    const auto pt_arr  = make_test_bytes<64>(0xD0U); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)

    // PSA encrypt
    auto psa_attrs = RealPsaBackend::make_aes256_gcm_encrypt_attrs();
    RealPsaBackend::KeyId psa_id = RealPsaBackend::null_key_id();
    ASSERT_EQ(RealPsaBackend::import_key(&psa_attrs, key.data(), key.size(), &psa_id),
              RealPsaBackend::ok);
    std::array<uint8_t, 64 + 16> psa_ct{}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    std::size_t psa_ct_len = 0;
    ASSERT_EQ(RealPsaBackend::aead_encrypt(
        psa_id, RealPsaBackend::alg_aes_gcm(),
        nonce.data(), nonce.size(),
        aad.data(), aad.size(),
        pt_arr.data(), pt_arr.size(),
        psa_ct.data(), psa_ct.size(), &psa_ct_len), RealPsaBackend::ok);
    RealPsaBackend::destroy_key(psa_id);

    // ARM ASM encrypt — same key, nonce, AAD, plaintext
    auto arm_attrs = ArmAsmBackend::make_aes256_gcm_encrypt_attrs();
    ArmAsmBackend::KeyId arm_id = ArmAsmBackend::null_key_id();
    ASSERT_EQ(ArmAsmBackend::import_key(&arm_attrs, key.data(), key.size(), &arm_id),
              ArmAsmBackend::ok);
    std::array<uint8_t, 64 + 16> arm_ct{}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    std::size_t arm_ct_len = 0;
    ASSERT_EQ(ArmAsmBackend::aead_encrypt(
        arm_id, ArmAsmBackend::alg_aes_gcm(),
        nonce.data(), nonce.size(),
        aad.data(), aad.size(),
        pt_arr.data(), pt_arr.size(),
        arm_ct.data(), arm_ct.size(), &arm_ct_len), ArmAsmBackend::ok);
    ArmAsmBackend::destroy_key(arm_id);

    ASSERT_EQ(psa_ct_len, arm_ct_len);
    expect_equal_outputs(psa_ct, arm_ct, "AES-256-GCM encrypt");
}

TEST_F(CrossProviderAesGcmTests, DecryptParity) {
    const auto key    = make_test_bytes<32>(0xE0U);
    const auto nonce  = make_test_bytes<12>(0xF0U);
    const auto pt_arr = make_test_bytes<48>(0x01U); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)

    // Produce ciphertext via PSA, then decrypt with both and compare plaintexts.
    auto psa_enc_attrs = RealPsaBackend::make_aes256_gcm_encrypt_attrs();
    RealPsaBackend::KeyId psa_enc_id = RealPsaBackend::null_key_id();
    ASSERT_EQ(RealPsaBackend::import_key(&psa_enc_attrs, key.data(), key.size(), &psa_enc_id),
              RealPsaBackend::ok);
    std::array<uint8_t, 48 + 16> ct{}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    std::size_t ct_len = 0;
    ASSERT_EQ(RealPsaBackend::aead_encrypt(
        psa_enc_id, RealPsaBackend::alg_aes_gcm(),
        nonce.data(), nonce.size(), nullptr, 0,
        pt_arr.data(), pt_arr.size(),
        ct.data(), ct.size(), &ct_len), RealPsaBackend::ok);
    RealPsaBackend::destroy_key(psa_enc_id);

    // PSA decrypt
    auto psa_dec_attrs = RealPsaBackend::make_aes256_gcm_decrypt_attrs();
    RealPsaBackend::KeyId psa_dec_id = RealPsaBackend::null_key_id();
    ASSERT_EQ(RealPsaBackend::import_key(&psa_dec_attrs, key.data(), key.size(), &psa_dec_id),
              RealPsaBackend::ok);
    std::array<uint8_t, 48> psa_pt{}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    std::size_t psa_pt_len = 0;
    ASSERT_EQ(RealPsaBackend::aead_decrypt(
        psa_dec_id, RealPsaBackend::alg_aes_gcm(),
        nonce.data(), nonce.size(), nullptr, 0,
        ct.data(), ct_len,
        psa_pt.data(), psa_pt.size(), &psa_pt_len), RealPsaBackend::ok);
    RealPsaBackend::destroy_key(psa_dec_id);

    // ARM ASM decrypt of same ciphertext
    auto arm_dec_attrs = ArmAsmBackend::make_aes256_gcm_decrypt_attrs();
    ArmAsmBackend::KeyId arm_dec_id = ArmAsmBackend::null_key_id();
    ASSERT_EQ(ArmAsmBackend::import_key(&arm_dec_attrs, key.data(), key.size(), &arm_dec_id),
              ArmAsmBackend::ok);
    std::array<uint8_t, 48> arm_pt{}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    std::size_t arm_pt_len = 0;
    ASSERT_EQ(ArmAsmBackend::aead_decrypt(
        arm_dec_id, ArmAsmBackend::alg_aes_gcm(),
        nonce.data(), nonce.size(), nullptr, 0,
        ct.data(), ct_len,
        arm_pt.data(), arm_pt.size(), &arm_pt_len), ArmAsmBackend::ok);
    ArmAsmBackend::destroy_key(arm_dec_id);

    ASSERT_EQ(psa_pt_len, arm_pt_len);
    expect_equal_outputs(psa_pt, arm_pt, "AES-256-GCM decrypt");
}


// ---------------------------------------------------------------------------
// ChaCha20-Poly1305 parity
// ---------------------------------------------------------------------------

class CrossProviderChaCha20Tests : public CrossProviderTest {};

TEST_F(CrossProviderChaCha20Tests, EncryptParity) {
    const auto key    = make_test_bytes<32>(0x11U);
    const auto nonce  = make_test_bytes<12>(0x22U);
    const auto aad    = make_test_bytes<16>(0x33U);
    const auto pt_arr = make_test_bytes<64>(0x44U); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)

    auto psa_attrs = RealPsaBackend::make_chacha20_poly1305_encrypt_attrs();
    RealPsaBackend::KeyId psa_id = RealPsaBackend::null_key_id();
    ASSERT_EQ(RealPsaBackend::import_key(&psa_attrs, key.data(), key.size(), &psa_id),
              RealPsaBackend::ok);
    std::array<uint8_t, 64 + 16> psa_ct{}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    std::size_t psa_ct_len = 0;
    ASSERT_EQ(RealPsaBackend::aead_encrypt(
        psa_id, RealPsaBackend::alg_chacha20_poly1305(),
        nonce.data(), nonce.size(),
        aad.data(), aad.size(),
        pt_arr.data(), pt_arr.size(),
        psa_ct.data(), psa_ct.size(), &psa_ct_len), RealPsaBackend::ok);
    RealPsaBackend::destroy_key(psa_id);

    auto arm_attrs = ArmAsmBackend::make_chacha20_poly1305_encrypt_attrs();
    ArmAsmBackend::KeyId arm_id = ArmAsmBackend::null_key_id();
    ASSERT_EQ(ArmAsmBackend::import_key(&arm_attrs, key.data(), key.size(), &arm_id),
              ArmAsmBackend::ok);
    std::array<uint8_t, 64 + 16> arm_ct{}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    std::size_t arm_ct_len = 0;
    ASSERT_EQ(ArmAsmBackend::aead_encrypt(
        arm_id, ArmAsmBackend::alg_chacha20_poly1305(),
        nonce.data(), nonce.size(),
        aad.data(), aad.size(),
        pt_arr.data(), pt_arr.size(),
        arm_ct.data(), arm_ct.size(), &arm_ct_len), ArmAsmBackend::ok);
    ArmAsmBackend::destroy_key(arm_id);

    ASSERT_EQ(psa_ct_len, arm_ct_len);
    expect_equal_outputs(psa_ct, arm_ct, "ChaCha20-Poly1305 encrypt");
}

TEST_F(CrossProviderChaCha20Tests, DecryptParity) {
    const auto key    = make_test_bytes<32>(0x55U);
    const auto nonce  = make_test_bytes<12>(0x66U);
    const auto pt_arr = make_test_bytes<80>(0x77U); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)

    // Encrypt via PSA, then decrypt via both and compare.
    auto psa_enc_attrs = RealPsaBackend::make_chacha20_poly1305_encrypt_attrs();
    RealPsaBackend::KeyId psa_enc_id = RealPsaBackend::null_key_id();
    ASSERT_EQ(RealPsaBackend::import_key(&psa_enc_attrs, key.data(), key.size(), &psa_enc_id),
              RealPsaBackend::ok);
    std::array<uint8_t, 80 + 16> ct{}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    std::size_t ct_len = 0;
    ASSERT_EQ(RealPsaBackend::aead_encrypt(
        psa_enc_id, RealPsaBackend::alg_chacha20_poly1305(),
        nonce.data(), nonce.size(), nullptr, 0,
        pt_arr.data(), pt_arr.size(),
        ct.data(), ct.size(), &ct_len), RealPsaBackend::ok);
    RealPsaBackend::destroy_key(psa_enc_id);

    // PSA decrypt
    auto psa_dec_attrs = RealPsaBackend::make_chacha20_poly1305_decrypt_attrs();
    RealPsaBackend::KeyId psa_dec_id = RealPsaBackend::null_key_id();
    ASSERT_EQ(RealPsaBackend::import_key(&psa_dec_attrs, key.data(), key.size(), &psa_dec_id),
              RealPsaBackend::ok);
    std::array<uint8_t, 80> psa_pt{}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    std::size_t psa_pt_len = 0;
    ASSERT_EQ(RealPsaBackend::aead_decrypt(
        psa_dec_id, RealPsaBackend::alg_chacha20_poly1305(),
        nonce.data(), nonce.size(), nullptr, 0,
        ct.data(), ct_len,
        psa_pt.data(), psa_pt.size(), &psa_pt_len), RealPsaBackend::ok);
    RealPsaBackend::destroy_key(psa_dec_id);

    // ARM ASM decrypt
    auto arm_dec_attrs = ArmAsmBackend::make_chacha20_poly1305_decrypt_attrs();
    ArmAsmBackend::KeyId arm_dec_id = ArmAsmBackend::null_key_id();
    ASSERT_EQ(ArmAsmBackend::import_key(&arm_dec_attrs, key.data(), key.size(), &arm_dec_id),
              ArmAsmBackend::ok);
    std::array<uint8_t, 80> arm_pt{}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    std::size_t arm_pt_len = 0;
    ASSERT_EQ(ArmAsmBackend::aead_decrypt(
        arm_dec_id, ArmAsmBackend::alg_chacha20_poly1305(),
        nonce.data(), nonce.size(), nullptr, 0,
        ct.data(), ct_len,
        arm_pt.data(), arm_pt.size(), &arm_pt_len), ArmAsmBackend::ok);
    ArmAsmBackend::destroy_key(arm_dec_id);

    ASSERT_EQ(psa_pt_len, arm_pt_len);
    expect_equal_outputs(psa_pt, arm_pt, "ChaCha20-Poly1305 decrypt");
}

// Cross-decryption: ARM ASM ciphertext must be accepted by PSA and vice versa.
TEST_F(CrossProviderChaCha20Tests, CrossDecryptArmCtWithPsa) {
    const auto key    = make_test_bytes<32>(0x88U);
    const auto nonce  = make_test_bytes<12>(0x99U);
    const auto pt_arr = make_test_bytes<32>(0xAAU);

    // ARM ASM encrypt
    auto arm_enc_attrs = ArmAsmBackend::make_chacha20_poly1305_encrypt_attrs();
    ArmAsmBackend::KeyId arm_enc_id = ArmAsmBackend::null_key_id();
    ASSERT_EQ(ArmAsmBackend::import_key(&arm_enc_attrs, key.data(), key.size(), &arm_enc_id),
              ArmAsmBackend::ok);
    std::array<uint8_t, 32 + 16> arm_ct{};
    std::size_t arm_ct_len = 0;
    ASSERT_EQ(ArmAsmBackend::aead_encrypt(
        arm_enc_id, ArmAsmBackend::alg_chacha20_poly1305(),
        nonce.data(), nonce.size(), nullptr, 0,
        pt_arr.data(), pt_arr.size(),
        arm_ct.data(), arm_ct.size(), &arm_ct_len), ArmAsmBackend::ok);
    ArmAsmBackend::destroy_key(arm_enc_id);

    // PSA decrypt of ARM ciphertext
    auto psa_dec_attrs = RealPsaBackend::make_chacha20_poly1305_decrypt_attrs();
    RealPsaBackend::KeyId psa_dec_id = RealPsaBackend::null_key_id();
    ASSERT_EQ(RealPsaBackend::import_key(&psa_dec_attrs, key.data(), key.size(), &psa_dec_id),
              RealPsaBackend::ok);
    std::array<uint8_t, 32> recovered_pt{};
    std::size_t recovered_len = 0;
    ASSERT_EQ(RealPsaBackend::aead_decrypt(
        psa_dec_id, RealPsaBackend::alg_chacha20_poly1305(),
        nonce.data(), nonce.size(), nullptr, 0,
        arm_ct.data(), arm_ct_len,
        recovered_pt.data(), recovered_pt.size(), &recovered_len), RealPsaBackend::ok)
        << "PSA rejected ciphertext produced by ARM ASM";
    RealPsaBackend::destroy_key(psa_dec_id);

    ASSERT_EQ(recovered_len, pt_arr.size());
    expect_equal_outputs(pt_arr, recovered_pt, "ChaCha20-Poly1305 cross-decrypt ARM→PSA");
}

TEST_F(CrossProviderChaCha20Tests, CrossDecryptPsaCtWithArm) {
    const auto key    = make_test_bytes<32>(0xBBU);
    const auto nonce  = make_test_bytes<12>(0xCCU);
    const auto pt_arr = make_test_bytes<32>(0xDDU);

    // PSA encrypt
    auto psa_enc_attrs = RealPsaBackend::make_chacha20_poly1305_encrypt_attrs();
    RealPsaBackend::KeyId psa_enc_id = RealPsaBackend::null_key_id();
    ASSERT_EQ(RealPsaBackend::import_key(&psa_enc_attrs, key.data(), key.size(), &psa_enc_id),
              RealPsaBackend::ok);
    std::array<uint8_t, 32 + 16> psa_ct{};
    std::size_t psa_ct_len = 0;
    ASSERT_EQ(RealPsaBackend::aead_encrypt(
        psa_enc_id, RealPsaBackend::alg_chacha20_poly1305(),
        nonce.data(), nonce.size(), nullptr, 0,
        pt_arr.data(), pt_arr.size(),
        psa_ct.data(), psa_ct.size(), &psa_ct_len), RealPsaBackend::ok);
    RealPsaBackend::destroy_key(psa_enc_id);

    // ARM ASM decrypt of PSA ciphertext
    auto arm_dec_attrs = ArmAsmBackend::make_chacha20_poly1305_decrypt_attrs();
    ArmAsmBackend::KeyId arm_dec_id = ArmAsmBackend::null_key_id();
    ASSERT_EQ(ArmAsmBackend::import_key(&arm_dec_attrs, key.data(), key.size(), &arm_dec_id),
              ArmAsmBackend::ok);
    std::array<uint8_t, 32> recovered_pt{};
    std::size_t recovered_len = 0;
    ASSERT_EQ(ArmAsmBackend::aead_decrypt(
        arm_dec_id, ArmAsmBackend::alg_chacha20_poly1305(),
        nonce.data(), nonce.size(), nullptr, 0,
        psa_ct.data(), psa_ct_len,
        recovered_pt.data(), recovered_pt.size(), &recovered_len), ArmAsmBackend::ok)
        << "ARM ASM rejected ciphertext produced by PSA";
    ArmAsmBackend::destroy_key(arm_dec_id);

    ASSERT_EQ(recovered_len, pt_arr.size());
    expect_equal_outputs(pt_arr, recovered_pt, "ChaCha20-Poly1305 cross-decrypt PSA→ARM");
}


// ---------------------------------------------------------------------------
// HKDF-SHA-384 parity
// ---------------------------------------------------------------------------

class CrossProviderHkdfTests : public CrossProviderTest {};

TEST_F(CrossProviderHkdfTests, HkdfSha384Parity) {
    // Fixed IKM, salt, info to make the test deterministic.
    const auto ikm_arr  = make_test_bytes<96>(0x10U); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    const auto salt_arr = make_test_bytes<13>(0x20U);
    const auto info_arr = make_test_bytes<10>(0x30U);
    constexpr std::size_t output_len = 48; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)

    // Helper lambda: run HKDF through one provider, return 48-byte output.
    auto run_hkdf = [&]<typename Provider>() -> std::array<uint8_t, output_len> {
        // IKM must go in as a key.
        auto attrs = Provider::make_hkdf_derive_attrs(ikm_arr.size() * 8U); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        typename Provider::KeyId id = Provider::null_key_id();
        if (Provider::import_key(&attrs, ikm_arr.data(), ikm_arr.size(), &id) != Provider::ok) {
            ADD_FAILURE() << "HKDF key import failed";
            return {};
        }

        auto op = Provider::make_kdf_op();
        if (Provider::key_derivation_setup(&op, Provider::alg_hkdf()) != Provider::ok) {
            ADD_FAILURE() << "HKDF setup failed";
            Provider::destroy_key(id);
            return {};
        }
        Provider::key_derivation_input_bytes(&op, Provider::kdf_step_salt(),
                                              salt_arr.data(), salt_arr.size());
        Provider::key_derivation_input_key(&op, Provider::kdf_step_secret(), id);
        Provider::key_derivation_input_bytes(&op, Provider::kdf_step_info(),
                                              info_arr.data(), info_arr.size());

        std::array<uint8_t, output_len> out{};
        if (Provider::key_derivation_output_bytes(&op, out.data(), out.size()) != Provider::ok) {
            ADD_FAILURE() << "HKDF output_bytes failed";
        }
        Provider::key_derivation_abort(&op);
        Provider::destroy_key(id);
        return out;
    };

    const auto psa_out = run_hkdf.template operator()<RealPsaBackend>();
    const auto arm_out = run_hkdf.template operator()<ArmAsmBackend>();
    expect_equal_outputs(psa_out, arm_out, "HKDF-SHA-384");
}

#endif  // SAFE_CRYPTO_PROVIDER_ARM_ASM
