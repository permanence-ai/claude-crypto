// SPDX-License-Identifier: Apache-2.0

#pragma once

// Cross-provider parity tests: native ASM backend vs PSA/MbedTLS.
//
// Each test generates a random input, runs the same operation through both
// NativeAsmBackend (NativeAsmBackend or IaAsmBackend) and RealPsaBackend, and
// asserts byte-for-byte identical output.  This catches implementation drift
// that KAT tests cannot find — a wrong implementation can still pass a KAT if
// the reference vector was derived from the same wrong code.
//
// Operations covered:
//   SHA-256, SHA-384, SHA-512
//   SHA3-256, SHA3-384, SHA3-512
//   HMAC-SHA-256, HMAC-SHA-384, HMAC-SHA-512
//   HMAC-SHA3-256, HMAC-SHA3-384, HMAC-SHA3-512
//   AES-256-GCM encrypt+decrypt parity; cross-decrypt both directions
//   ChaCha20-Poly1305 encrypt+decrypt parity; cross-decrypt both directions
//   HKDF-SHA-384 (extract+expand) parity; HKDF-Expand-only parity
//   ECDH shared-secret parity for P-256, P-384, P-521
//   ECDSA cross-verify for P-384 (both providers use SHA-384 on this curve)
//   RSA-OAEP cross-decrypt for 3072-bit and 4096-bit keys
//   RSA-PSS cross-verify for 3072-bit and 4096-bit keys
//
// The file is always compiled but the tests are guarded by
// SAFE_CRYPTO_PROVIDER_ARM_ASM or SAFE_CRYPTO_PROVIDER_IA_ASM.

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

#if defined(SAFE_CRYPTO_PROVIDER_IA_ASM)
#  include "ia_asm_backend.hpp"
using NativeAsmBackend = IaAsmBackend;
#elif defined(SAFE_CRYPTO_ARM_ASM_AVAILABLE)
#  include "arm_asm_backend.hpp"
using NativeAsmBackend = ArmAsmBackend;
#endif
#include "psa_mbedtls_backend.hpp"

#include "aead.hpp"
#include "asymmetric.hpp"
#include "digests.hpp"
#include "ecc.hpp"
#include "ecdh.hpp"
#include "kdf.hpp"
#include "mac.hpp"

#include "test_utils.hpp"

#if defined(SAFE_CRYPTO_PROVIDER_IA_ASM) || defined(SAFE_CRYPTO_ARM_ASM_AVAILABLE)


// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Fill a raw byte array with a deterministic pattern seeded from index.
template<std::size_t N>
static ByteArray< N> make_test_bytes(uint8_t seed = 0) {
    ByteArray< N> out{};
    for (std::size_t i = 0; i < N; ++i) {
        out[i] = static_cast<uint8_t>((i ^ seed) & 0xFFU); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    }
    return out;
}

// Compare two fixed-size output buffers and report the first differing byte.
template<std::size_t N>
static void expect_equal_outputs(const ByteArray< N>& psa,
                                  const ByteArray< N>& arm,
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
        ByteArray< out_size> psa_out{};
        ByteArray< out_size> arm_out{};
        std::size_t psa_len = 0, arm_len = 0;

        ASSERT_EQ(RealPsaBackend::hash_compute(
            RealPsaBackend::alg_sha(V), msg.data(), msg.size(),
            psa_out.data(), psa_out.size(), &psa_len), RealPsaBackend::ok)
            << label << " PSA hash_compute failed (msg_len=" << msg_len << ")";

        ASSERT_EQ(NativeAsmBackend::hash_compute(
            NativeAsmBackend::alg_sha(V), msg.data(), msg.size(),
            arm_out.data(), arm_out.size(), &arm_len), NativeAsmBackend::ok)
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
    ByteArray< out_size> psa_out{};
    ByteArray< out_size> arm_out{};
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
    (void)RealPsaBackend::destroy_key(psa_id);

    // Import key into ARM ASM store.
    auto arm_attrs = NativeAsmBackend::make_hmac_generate_attrs(V, key.size() * 8U); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    NativeAsmBackend::KeyId arm_id = NativeAsmBackend::null_key_id();
    ASSERT_EQ(NativeAsmBackend::import_key(&arm_attrs, key.data(), key.size(), &arm_id),
              NativeAsmBackend::ok) << label << " ARM key import failed";

    ASSERT_EQ(NativeAsmBackend::mac_compute(
        arm_id, NativeAsmBackend::alg_hmac(V),
        msg.data(), msg.size(),
        arm_out.data(), arm_out.size(), &arm_len), NativeAsmBackend::ok)
        << label << " ARM mac_compute failed";
    (void)NativeAsmBackend::destroy_key(arm_id);

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
// Disabled on IA_ASM when AES-NI is off (SAFE_CRYPTO_IA_ASM_AES_NI=OFF).
// ---------------------------------------------------------------------------

#if !defined(SAFE_CRYPTO_PROVIDER_IA_ASM) || defined(IA_ASM_AES_NI_ENABLED)
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
    ByteArray< 64 + aes_gcm_tag_bytes> psa_ct{}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    std::size_t psa_ct_len = 0;
    ASSERT_EQ(RealPsaBackend::aead_encrypt(
        psa_id, RealPsaBackend::alg_aes_gcm(),
        nonce.data(), nonce.size(),
        aad.data(), aad.size(),
        pt_arr.data(), pt_arr.size(),
        psa_ct.data(), psa_ct.size(), &psa_ct_len), RealPsaBackend::ok);
    (void)RealPsaBackend::destroy_key(psa_id);

    // ARM ASM encrypt — same key, nonce, AAD, plaintext
    auto arm_attrs = NativeAsmBackend::make_aes256_gcm_encrypt_attrs();
    NativeAsmBackend::KeyId arm_id = NativeAsmBackend::null_key_id();
    ASSERT_EQ(NativeAsmBackend::import_key(&arm_attrs, key.data(), key.size(), &arm_id),
              NativeAsmBackend::ok);
    ByteArray< 64 + aes_gcm_tag_bytes> arm_ct{}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    std::size_t arm_ct_len = 0;
    ASSERT_EQ(NativeAsmBackend::aead_encrypt(
        arm_id, NativeAsmBackend::alg_aes_gcm(),
        nonce.data(), nonce.size(),
        aad.data(), aad.size(),
        pt_arr.data(), pt_arr.size(),
        arm_ct.data(), arm_ct.size(), &arm_ct_len), NativeAsmBackend::ok);
    (void)NativeAsmBackend::destroy_key(arm_id);

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
    ByteArray< 48 + aes_gcm_tag_bytes> ct{}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    std::size_t ct_len = 0;
    ASSERT_EQ(RealPsaBackend::aead_encrypt(
        psa_enc_id, RealPsaBackend::alg_aes_gcm(),
        nonce.data(), nonce.size(), nullptr, 0,
        pt_arr.data(), pt_arr.size(),
        ct.data(), ct.size(), &ct_len), RealPsaBackend::ok);
    (void)RealPsaBackend::destroy_key(psa_enc_id);

    // PSA decrypt
    auto psa_dec_attrs = RealPsaBackend::make_aes256_gcm_decrypt_attrs();
    RealPsaBackend::KeyId psa_dec_id = RealPsaBackend::null_key_id();
    ASSERT_EQ(RealPsaBackend::import_key(&psa_dec_attrs, key.data(), key.size(), &psa_dec_id),
              RealPsaBackend::ok);
    ByteArray< 48> psa_pt{}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    std::size_t psa_pt_len = 0;
    ASSERT_EQ(RealPsaBackend::aead_decrypt(
        psa_dec_id, RealPsaBackend::alg_aes_gcm(),
        nonce.data(), nonce.size(), nullptr, 0,
        ct.data(), ct_len,
        psa_pt.data(), psa_pt.size(), &psa_pt_len), RealPsaBackend::ok);
    (void)RealPsaBackend::destroy_key(psa_dec_id);

    // ARM ASM decrypt of same ciphertext
    auto arm_dec_attrs = NativeAsmBackend::make_aes256_gcm_decrypt_attrs();
    NativeAsmBackend::KeyId arm_dec_id = NativeAsmBackend::null_key_id();
    ASSERT_EQ(NativeAsmBackend::import_key(&arm_dec_attrs, key.data(), key.size(), &arm_dec_id),
              NativeAsmBackend::ok);
    ByteArray< 48> arm_pt{}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    std::size_t arm_pt_len = 0;
    ASSERT_EQ(NativeAsmBackend::aead_decrypt(
        arm_dec_id, NativeAsmBackend::alg_aes_gcm(),
        nonce.data(), nonce.size(), nullptr, 0,
        ct.data(), ct_len,
        arm_pt.data(), arm_pt.size(), &arm_pt_len), NativeAsmBackend::ok);
    (void)NativeAsmBackend::destroy_key(arm_dec_id);

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
    ByteArray< 64 + chacha20_poly1305_tag_bytes> psa_ct{}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    std::size_t psa_ct_len = 0;
    ASSERT_EQ(RealPsaBackend::aead_encrypt(
        psa_id, RealPsaBackend::alg_chacha20_poly1305(),
        nonce.data(), nonce.size(),
        aad.data(), aad.size(),
        pt_arr.data(), pt_arr.size(),
        psa_ct.data(), psa_ct.size(), &psa_ct_len), RealPsaBackend::ok);
    (void)RealPsaBackend::destroy_key(psa_id);

    auto arm_attrs = NativeAsmBackend::make_chacha20_poly1305_encrypt_attrs();
    NativeAsmBackend::KeyId arm_id = NativeAsmBackend::null_key_id();
    ASSERT_EQ(NativeAsmBackend::import_key(&arm_attrs, key.data(), key.size(), &arm_id),
              NativeAsmBackend::ok);
    ByteArray< 64 + chacha20_poly1305_tag_bytes> arm_ct{}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    std::size_t arm_ct_len = 0;
    ASSERT_EQ(NativeAsmBackend::aead_encrypt(
        arm_id, NativeAsmBackend::alg_chacha20_poly1305(),
        nonce.data(), nonce.size(),
        aad.data(), aad.size(),
        pt_arr.data(), pt_arr.size(),
        arm_ct.data(), arm_ct.size(), &arm_ct_len), NativeAsmBackend::ok);
    (void)NativeAsmBackend::destroy_key(arm_id);

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
    ByteArray< 80 + chacha20_poly1305_tag_bytes> ct{}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    std::size_t ct_len = 0;
    ASSERT_EQ(RealPsaBackend::aead_encrypt(
        psa_enc_id, RealPsaBackend::alg_chacha20_poly1305(),
        nonce.data(), nonce.size(), nullptr, 0,
        pt_arr.data(), pt_arr.size(),
        ct.data(), ct.size(), &ct_len), RealPsaBackend::ok);
    (void)RealPsaBackend::destroy_key(psa_enc_id);

    // PSA decrypt
    auto psa_dec_attrs = RealPsaBackend::make_chacha20_poly1305_decrypt_attrs();
    RealPsaBackend::KeyId psa_dec_id = RealPsaBackend::null_key_id();
    ASSERT_EQ(RealPsaBackend::import_key(&psa_dec_attrs, key.data(), key.size(), &psa_dec_id),
              RealPsaBackend::ok);
    ByteArray< 80> psa_pt{}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    std::size_t psa_pt_len = 0;
    ASSERT_EQ(RealPsaBackend::aead_decrypt(
        psa_dec_id, RealPsaBackend::alg_chacha20_poly1305(),
        nonce.data(), nonce.size(), nullptr, 0,
        ct.data(), ct_len,
        psa_pt.data(), psa_pt.size(), &psa_pt_len), RealPsaBackend::ok);
    (void)RealPsaBackend::destroy_key(psa_dec_id);

    // ARM ASM decrypt
    auto arm_dec_attrs = NativeAsmBackend::make_chacha20_poly1305_decrypt_attrs();
    NativeAsmBackend::KeyId arm_dec_id = NativeAsmBackend::null_key_id();
    ASSERT_EQ(NativeAsmBackend::import_key(&arm_dec_attrs, key.data(), key.size(), &arm_dec_id),
              NativeAsmBackend::ok);
    ByteArray< 80> arm_pt{}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    std::size_t arm_pt_len = 0;
    ASSERT_EQ(NativeAsmBackend::aead_decrypt(
        arm_dec_id, NativeAsmBackend::alg_chacha20_poly1305(),
        nonce.data(), nonce.size(), nullptr, 0,
        ct.data(), ct_len,
        arm_pt.data(), arm_pt.size(), &arm_pt_len), NativeAsmBackend::ok);
    (void)NativeAsmBackend::destroy_key(arm_dec_id);

    ASSERT_EQ(psa_pt_len, arm_pt_len);
    expect_equal_outputs(psa_pt, arm_pt, "ChaCha20-Poly1305 decrypt");
}

// Cross-decryption: ARM ASM ciphertext must be accepted by PSA and vice versa.
TEST_F(CrossProviderChaCha20Tests, CrossDecryptArmCtWithPsa) {
    const auto key    = make_test_bytes<32>(0x88U);
    const auto nonce  = make_test_bytes<12>(0x99U);
    const auto pt_arr = make_test_bytes<32>(0xAAU);

    // ARM ASM encrypt
    auto arm_enc_attrs = NativeAsmBackend::make_chacha20_poly1305_encrypt_attrs();
    NativeAsmBackend::KeyId arm_enc_id = NativeAsmBackend::null_key_id();
    ASSERT_EQ(NativeAsmBackend::import_key(&arm_enc_attrs, key.data(), key.size(), &arm_enc_id),
              NativeAsmBackend::ok);
    ByteArray< 32 + 16> arm_ct{};
    std::size_t arm_ct_len = 0;
    ASSERT_EQ(NativeAsmBackend::aead_encrypt(
        arm_enc_id, NativeAsmBackend::alg_chacha20_poly1305(),
        nonce.data(), nonce.size(), nullptr, 0,
        pt_arr.data(), pt_arr.size(),
        arm_ct.data(), arm_ct.size(), &arm_ct_len), NativeAsmBackend::ok);
    (void)NativeAsmBackend::destroy_key(arm_enc_id);

    // PSA decrypt of ARM ciphertext
    auto psa_dec_attrs = RealPsaBackend::make_chacha20_poly1305_decrypt_attrs();
    RealPsaBackend::KeyId psa_dec_id = RealPsaBackend::null_key_id();
    ASSERT_EQ(RealPsaBackend::import_key(&psa_dec_attrs, key.data(), key.size(), &psa_dec_id),
              RealPsaBackend::ok);
    ByteArray< 32> recovered_pt{};
    std::size_t recovered_len = 0;
    ASSERT_EQ(RealPsaBackend::aead_decrypt(
        psa_dec_id, RealPsaBackend::alg_chacha20_poly1305(),
        nonce.data(), nonce.size(), nullptr, 0,
        arm_ct.data(), arm_ct_len,
        recovered_pt.data(), recovered_pt.size(), &recovered_len), RealPsaBackend::ok)
        << "PSA rejected ciphertext produced by ARM ASM";
    (void)RealPsaBackend::destroy_key(psa_dec_id);

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
    ByteArray< 32 + 16> psa_ct{};
    std::size_t psa_ct_len = 0;
    ASSERT_EQ(RealPsaBackend::aead_encrypt(
        psa_enc_id, RealPsaBackend::alg_chacha20_poly1305(),
        nonce.data(), nonce.size(), nullptr, 0,
        pt_arr.data(), pt_arr.size(),
        psa_ct.data(), psa_ct.size(), &psa_ct_len), RealPsaBackend::ok);
    (void)RealPsaBackend::destroy_key(psa_enc_id);

    // ARM ASM decrypt of PSA ciphertext
    auto arm_dec_attrs = NativeAsmBackend::make_chacha20_poly1305_decrypt_attrs();
    NativeAsmBackend::KeyId arm_dec_id = NativeAsmBackend::null_key_id();
    ASSERT_EQ(NativeAsmBackend::import_key(&arm_dec_attrs, key.data(), key.size(), &arm_dec_id),
              NativeAsmBackend::ok);
    ByteArray< 32> recovered_pt{};
    std::size_t recovered_len = 0;
    ASSERT_EQ(NativeAsmBackend::aead_decrypt(
        arm_dec_id, NativeAsmBackend::alg_chacha20_poly1305(),
        nonce.data(), nonce.size(), nullptr, 0,
        psa_ct.data(), psa_ct_len,
        recovered_pt.data(), recovered_pt.size(), &recovered_len), NativeAsmBackend::ok)
        << "ARM ASM rejected ciphertext produced by PSA";
    (void)NativeAsmBackend::destroy_key(arm_dec_id);

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
    constexpr std::size_t output_len = sha384_digest_bytes;

    // Helper lambda: run HKDF through one provider, return 48-byte output.
    auto run_hkdf = [&]<typename Provider>() -> ByteArray< output_len> {
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
            (void)Provider::destroy_key(id);
            return {};
        }
        if (Provider::key_derivation_input_bytes(&op, Provider::kdf_step_salt(),
                                                  salt_arr.data(), salt_arr.size()) != Provider::ok) {
            ADD_FAILURE() << "HKDF salt input failed";
        }
        if (Provider::key_derivation_input_key(&op, Provider::kdf_step_secret(), id) != Provider::ok) {
            ADD_FAILURE() << "HKDF key input failed";
        }
        if (Provider::key_derivation_input_bytes(&op, Provider::kdf_step_info(),
                                                  info_arr.data(), info_arr.size()) != Provider::ok) {
            ADD_FAILURE() << "HKDF info input failed";
        }

        ByteArray< output_len> out{};
        if (Provider::key_derivation_output_bytes(&op, out.data(), out.size()) != Provider::ok) {
            ADD_FAILURE() << "HKDF output_bytes failed";
        }
        (void)Provider::key_derivation_abort(&op);
        (void)Provider::destroy_key(id);
        return out;
    };

    const auto psa_out = run_hkdf.template operator()<RealPsaBackend>();
    const auto arm_out = run_hkdf.template operator()<NativeAsmBackend>();
    expect_equal_outputs(psa_out, arm_out, "HKDF-SHA-384");
}


TEST_F(CrossProviderHkdfTests, HkdfExpandParity) {
    // Run HKDF-Expand (no salt/extract step) through both providers with the same PRK and info.
    const auto prk_arr  = make_test_bytes<48>(0x40U); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    const auto info_arr = make_test_bytes<12>(0x50U); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    constexpr std::size_t output_len = sha384_digest_bytes;

    auto run_hkdf_expand = [&]<typename Provider>() -> ByteArray< output_len> {
        auto attrs = Provider::make_hkdf_expand_derive_attrs(prk_arr.size() * 8U); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        typename Provider::KeyId id = Provider::null_key_id();
        if (Provider::import_key(&attrs, prk_arr.data(), prk_arr.size(), &id) != Provider::ok) {
            ADD_FAILURE() << "HKDF-Expand PRK import failed";
            return {};
        }

        auto op = Provider::make_kdf_op();
        if (Provider::key_derivation_setup(&op, Provider::alg_hkdf_expand()) != Provider::ok) {
            ADD_FAILURE() << "HKDF-Expand setup failed";
            (void)Provider::destroy_key(id);
            return {};
        }
        if (Provider::key_derivation_input_key(&op, Provider::kdf_step_secret(), id) != Provider::ok) {
            ADD_FAILURE() << "HKDF-Expand PRK key input failed";
        }
        if (Provider::key_derivation_input_bytes(&op, Provider::kdf_step_info(),
                                                  info_arr.data(), info_arr.size()) != Provider::ok) {
            ADD_FAILURE() << "HKDF-Expand info input failed";
        }

        ByteArray< output_len> out{};
        if (Provider::key_derivation_output_bytes(&op, out.data(), out.size()) != Provider::ok) {
            ADD_FAILURE() << "HKDF-Expand output_bytes failed";
        }
        (void)Provider::key_derivation_abort(&op);
        (void)Provider::destroy_key(id);
        return out;
    };

    const auto psa_out = run_hkdf_expand.template operator()<RealPsaBackend>();
    const auto arm_out = run_hkdf_expand.template operator()<NativeAsmBackend>();
    expect_equal_outputs(psa_out, arm_out, "HKDF-Expand-SHA-384");
}


// ---------------------------------------------------------------------------
// AES-256-GCM cross-decrypt: ARM ASM encrypts, PSA decrypts
// ---------------------------------------------------------------------------

TEST_F(CrossProviderAesGcmTests, CrossDecryptArmCtWithPsa) {
    const auto key    = make_test_bytes<32>(0x10U);
    const auto nonce  = make_test_bytes<12>(0x11U);
    const auto pt_arr = make_test_bytes<48>(0x12U); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)

    // ARM ASM encrypt
    auto arm_enc_attrs = NativeAsmBackend::make_aes256_gcm_encrypt_attrs();
    NativeAsmBackend::KeyId arm_enc_id = NativeAsmBackend::null_key_id();
    ASSERT_EQ(NativeAsmBackend::import_key(&arm_enc_attrs, key.data(), key.size(), &arm_enc_id),
              NativeAsmBackend::ok);
    ByteArray< 48 + aes_gcm_tag_bytes> arm_ct{}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    std::size_t arm_ct_len = 0;
    ASSERT_EQ(NativeAsmBackend::aead_encrypt(
        arm_enc_id, NativeAsmBackend::alg_aes_gcm(),
        nonce.data(), nonce.size(), nullptr, 0,
        pt_arr.data(), pt_arr.size(),
        arm_ct.data(), arm_ct.size(), &arm_ct_len), NativeAsmBackend::ok);
    (void)NativeAsmBackend::destroy_key(arm_enc_id);

    // PSA decrypt of ARM ciphertext
    auto psa_dec_attrs = RealPsaBackend::make_aes256_gcm_decrypt_attrs();
    RealPsaBackend::KeyId psa_dec_id = RealPsaBackend::null_key_id();
    ASSERT_EQ(RealPsaBackend::import_key(&psa_dec_attrs, key.data(), key.size(), &psa_dec_id),
              RealPsaBackend::ok);
    ByteArray< 48> recovered_pt{}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    std::size_t recovered_len = 0;
    ASSERT_EQ(RealPsaBackend::aead_decrypt(
        psa_dec_id, RealPsaBackend::alg_aes_gcm(),
        nonce.data(), nonce.size(), nullptr, 0,
        arm_ct.data(), arm_ct_len,
        recovered_pt.data(), recovered_pt.size(), &recovered_len), RealPsaBackend::ok)
        << "PSA rejected AES-GCM ciphertext produced by ARM ASM";
    (void)RealPsaBackend::destroy_key(psa_dec_id);

    ASSERT_EQ(recovered_len, pt_arr.size());
    expect_equal_outputs(pt_arr, recovered_pt, "AES-256-GCM cross-decrypt ARM→PSA");
}

#endif // !SAFE_CRYPTO_PROVIDER_IA_ASM || IA_ASM_AES_NI_ENABLED


// ---------------------------------------------------------------------------
// ECDH parity: both providers derive identical shared secrets
//
// Strategy: generate an ECDH key pair with ARM ASM, export the raw private
// key bytes and the uncompressed public key (0x04|x|y).  Import the private
// key into PSA using its raw-scalar encoding (same bytes PSA expects).
// Generate a second ephemeral key pair with PSA for the peer side.
// Both providers compute raw_key_agreement with their respective private keys
// and the same peer public key; the x-coordinate shared secrets must be equal.
// ---------------------------------------------------------------------------

class CrossProviderEcdhTests : public CrossProviderTest {};

template<std::size_t KeyBits>
static void run_ecdh_parity_test(const char* label) {
    // Generate key A with ARM ASM.
    auto arm_gen_attrs = NativeAsmBackend::make_ecdh_generate_attrs(KeyBits);
    NativeAsmBackend::KeyId arm_id_a = NativeAsmBackend::null_key_id();
    ASSERT_EQ(NativeAsmBackend::generate_key(&arm_gen_attrs, &arm_id_a), NativeAsmBackend::ok)
        << label << " ARM key gen failed";

    // Export ARM private key scalar bytes.
    constexpr std::size_t sk_len = (KeyBits + 7U) / 8U;
    ByteArray< sk_len> arm_sk{};
    std::size_t arm_sk_len = 0;
    ASSERT_EQ(NativeAsmBackend::export_key(arm_id_a, arm_sk.data(), arm_sk.size(), &arm_sk_len),
              NativeAsmBackend::ok) << label << " ARM export_key failed";
    ASSERT_EQ(arm_sk_len, sk_len);

    // Derive ARM public key (uncompressed 0x04|x|y).
    constexpr std::size_t pk_len = sk_len * 2U + 1U;
    ByteArray< pk_len> arm_pk{};
    std::size_t arm_pk_len = 0;
    ASSERT_EQ(NativeAsmBackend::export_public_key(arm_id_a, arm_pk.data(), arm_pk.size(), &arm_pk_len),
              NativeAsmBackend::ok) << label << " ARM export_public_key failed";
    ASSERT_EQ(arm_pk_len, pk_len);

    // Import the same private key scalar into PSA as an ECDH key.
    auto psa_agree_attrs = RealPsaBackend::make_ecdh_agree_attrs(KeyBits);
    RealPsaBackend::KeyId psa_id_a = RealPsaBackend::null_key_id();
    ASSERT_EQ(RealPsaBackend::import_key(&psa_agree_attrs, arm_sk.data(), arm_sk_len, &psa_id_a),
              RealPsaBackend::ok) << label << " PSA key import failed";

    // Generate peer key B with PSA (export for peer public key).
    auto psa_gen_attrs = RealPsaBackend::make_ecdh_generate_attrs(KeyBits);
    RealPsaBackend::KeyId psa_id_b = RealPsaBackend::null_key_id();
    ASSERT_EQ(RealPsaBackend::generate_key(&psa_gen_attrs, &psa_id_b), RealPsaBackend::ok)
        << label << " PSA peer key gen failed";
    ByteArray< pk_len> peer_pk{};
    std::size_t peer_pk_len = 0;
    ASSERT_EQ(RealPsaBackend::export_public_key(psa_id_b, peer_pk.data(), peer_pk.size(), &peer_pk_len),
              RealPsaBackend::ok) << label << " PSA peer export_public_key failed";
    ASSERT_EQ(peer_pk_len, pk_len);

    // ARM ASM: raw_key_agreement(arm_id_a, peer_pk) → shared secret.
    ByteArray< sk_len> arm_ss{};
    std::size_t arm_ss_len = 0;
    ASSERT_EQ(NativeAsmBackend::raw_key_agreement(
        NativeAsmBackend::alg_ecdh(), arm_id_a,
        peer_pk.data(), peer_pk_len,
        arm_ss.data(), arm_ss.size(), &arm_ss_len), NativeAsmBackend::ok)
        << label << " ARM raw_key_agreement failed";

    // PSA: raw_key_agreement(psa_id_a, peer_pk) → shared secret (same private key, same peer).
    ByteArray< sk_len> psa_ss{};
    std::size_t psa_ss_len = 0;
    ASSERT_EQ(RealPsaBackend::raw_key_agreement(
        RealPsaBackend::alg_ecdh(), psa_id_a,
        peer_pk.data(), peer_pk_len,
        psa_ss.data(), psa_ss.size(), &psa_ss_len), RealPsaBackend::ok)
        << label << " PSA raw_key_agreement failed";

    (void)NativeAsmBackend::destroy_key(arm_id_a);
    (void)RealPsaBackend::destroy_key(psa_id_a);
    (void)RealPsaBackend::destroy_key(psa_id_b);

    ASSERT_EQ(arm_ss_len, psa_ss_len) << label << " shared secret length mismatch";
    expect_equal_outputs(arm_ss, psa_ss, label);
}

TEST_F(CrossProviderEcdhTests, EcdhParity_P256) { run_ecdh_parity_test<p256_bits>("ECDH-P256"); }
TEST_F(CrossProviderEcdhTests, EcdhParity_P384) { run_ecdh_parity_test<p384_bits>("ECDH-P384"); }
TEST_F(CrossProviderEcdhTests, EcdhParity_P521) { run_ecdh_parity_test<p521_bits>("ECDH-P521"); }


// ---------------------------------------------------------------------------
// ECDSA cross-verify: sign with one provider, verify with the other
//
// Key format bridge:
//   ARM ASM uses raw private key scalar (sk_len bytes) and uncompressed point
//   (0x04|x|y) for the public key.  PSA uses the same raw-scalar encoding for
//   import, and the same uncompressed-point format for PSA_KEY_TYPE_ECC_PUBLIC.
//   So we can share keys by exporting and re-importing.
//
// Hash algorithm note:
//   The ARM ASM backend uses curve-appropriate hashes: SHA-256 (P256), SHA-384
//   (P384), SHA-512 (P521).  The PSA backend's alg_ecdsa() uses SHA-384 for
//   all curves.  Cross-verify is therefore only possible for P384, where both
//   providers agree on SHA-384.  P256 and P521 are not tested here because the
//   two providers sign over different digests and are intentionally incompatible.
// ---------------------------------------------------------------------------

class CrossProviderEcdsaTests : public CrossProviderTest {};

template<std::size_t KeyBits>
static void run_ecdsa_cross_verify_test(const char* label) {
    const auto msg = make_test_bytes<64>(0x20U); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)

    constexpr std::size_t sk_len  = (KeyBits + 7U) / 8U;
    constexpr std::size_t pk_len  = sk_len * 2U + 1U;
    constexpr std::size_t sig_len = sk_len * 2U;

    // ---- ARM signs, PSA verifies ----------------------------------------
    {
        // Generate signing key with ARM.
        auto arm_sign_attrs = NativeAsmBackend::make_ecdsa_sign_attrs(KeyBits);
        NativeAsmBackend::KeyId arm_sign_id = NativeAsmBackend::null_key_id();
        ASSERT_EQ(NativeAsmBackend::generate_key(&arm_sign_attrs, &arm_sign_id), NativeAsmBackend::ok)
            << label << " ARM keygen failed";

        // ARM sign.
        ByteArray< sig_len> arm_sig{};
        std::size_t arm_sig_len = 0;
        ASSERT_EQ(NativeAsmBackend::sign_message(
            arm_sign_id, NativeAsmBackend::alg_ecdsa(),
            msg.data(), msg.size(),
            arm_sig.data(), arm_sig.size(), &arm_sig_len), NativeAsmBackend::ok)
            << label << " ARM sign failed";
        ASSERT_EQ(arm_sig_len, sig_len);

        // Export ARM public key (uncompressed point) and import into PSA for verification.
        ByteArray< pk_len> arm_pub{};
        std::size_t arm_pub_len = 0;
        ASSERT_EQ(NativeAsmBackend::export_public_key(
            arm_sign_id, arm_pub.data(), arm_pub.size(), &arm_pub_len), NativeAsmBackend::ok)
            << label << " ARM export_public_key failed";

        auto psa_verify_attrs = RealPsaBackend::make_ecdsa_verify_attrs(KeyBits);
        RealPsaBackend::KeyId psa_verify_id = RealPsaBackend::null_key_id();
        ASSERT_EQ(RealPsaBackend::import_key(
            &psa_verify_attrs, arm_pub.data(), arm_pub_len, &psa_verify_id), RealPsaBackend::ok)
            << label << " PSA public key import failed";

        EXPECT_EQ(RealPsaBackend::verify_message(
            psa_verify_id, RealPsaBackend::alg_ecdsa(),
            msg.data(), msg.size(),
            arm_sig.data(), arm_sig_len), RealPsaBackend::ok)
            << label << " PSA rejected ARM signature";

        (void)NativeAsmBackend::destroy_key(arm_sign_id);
        (void)RealPsaBackend::destroy_key(psa_verify_id);
    }

    // ---- PSA signs, ARM verifies ----------------------------------------
    {
        // Generate signing key with PSA (needs EXPORT to get private key for ARM import).
        auto psa_sig_gen_attrs = RealPsaBackend::make_ecdsa_generate_attrs(KeyBits);
        RealPsaBackend::KeyId psa_sign_id = RealPsaBackend::null_key_id();
        ASSERT_EQ(RealPsaBackend::generate_key(&psa_sig_gen_attrs, &psa_sign_id), RealPsaBackend::ok)
            << label << " PSA keygen failed";

        // PSA sign.
        ByteArray< sig_len> psa_sig{};
        std::size_t psa_sig_len = 0;
        ASSERT_EQ(RealPsaBackend::sign_message(
            psa_sign_id, RealPsaBackend::alg_ecdsa(),
            msg.data(), msg.size(),
            psa_sig.data(), psa_sig.size(), &psa_sig_len), RealPsaBackend::ok)
            << label << " PSA sign failed";
        ASSERT_EQ(psa_sig_len, sig_len);

        // Export PSA public key (uncompressed point) and import into ARM for verification.
        ByteArray< pk_len> psa_pub{};
        std::size_t psa_pub_len = 0;
        ASSERT_EQ(RealPsaBackend::export_public_key(
            psa_sign_id, psa_pub.data(), psa_pub.size(), &psa_pub_len), RealPsaBackend::ok)
            << label << " PSA export_public_key failed";
        ASSERT_EQ(psa_pub_len, pk_len);

        auto arm_verify_attrs = NativeAsmBackend::make_ecdsa_verify_attrs(KeyBits);
        NativeAsmBackend::KeyId arm_verify_id = NativeAsmBackend::null_key_id();
        ASSERT_EQ(NativeAsmBackend::import_key(
            &arm_verify_attrs, psa_pub.data(), psa_pub_len, &arm_verify_id), NativeAsmBackend::ok)
            << label << " ARM public key import failed";

        EXPECT_EQ(NativeAsmBackend::verify_message(
            arm_verify_id, NativeAsmBackend::alg_ecdsa(),
            msg.data(), msg.size(),
            psa_sig.data(), psa_sig_len), NativeAsmBackend::ok)
            << label << " ARM rejected PSA signature";

        (void)RealPsaBackend::destroy_key(psa_sign_id);
        (void)NativeAsmBackend::destroy_key(arm_verify_id);
    }
}

// Only P384: both providers use SHA-384 for ECDSA on this curve.
TEST_F(CrossProviderEcdsaTests, EcdsaCrossVerify_P384) { run_ecdsa_cross_verify_test<p384_bits>("ECDSA-P384"); }


// ---------------------------------------------------------------------------
// RSA cross-operations: OAEP cross-decrypt and PSS cross-verify
//
// Strategy: generate an RSA key pair with PSA (generate_rsa_key_impl), then
// import the private and public DER bytes into the ARM ASM backend for
// cross-encryption and cross-verification tests.
// ---------------------------------------------------------------------------

class CrossProviderRsaTests : public CrossProviderTest {};

// Shared test helper: generate a PSA RSA key pair (done once per test to avoid
// the ~6-second keygen cost), then run cross-direction tests.
template<RsaKeyBits KB>
static void run_rsa_oaep_cross_decrypt_test(const char* label) {
    constexpr std::size_t key_bits = static_cast<std::size_t>(static_cast<std::uint16_t>(KB));

    // Generate key pair with PSA.
    const auto kp = generate_rsa_key_impl<KB, RealPsaBackend>();
    ASSERT_TRUE(kp.has_value()) << label << " RSA keygen failed";

    const auto& priv_der = kp->private_key_der;
    const auto& pub_der  = kp->public_key_der;

    // ---- PSA encrypts, ARM decrypts -------------------------------------
    {
        const auto pt_arr = make_test_bytes<64>(0x61U); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)

        // PSA encrypt with public key.
        auto psa_enc_attrs = RealPsaBackend::make_rsa_oaep_encrypt_attrs(key_bits);
        RealPsaBackend::KeyId psa_enc_id = RealPsaBackend::null_key_id();
        ASSERT_EQ(RealPsaBackend::import_key(
            &psa_enc_attrs, pub_der.data(), pub_der.size(), &psa_enc_id), RealPsaBackend::ok)
            << label << " PSA public key import failed";

        const std::size_t ct_buf_size = RealPsaBackend::rsa_oaep_encrypt_output_size(key_bits);
        SecureBuffer psa_ct(ct_buf_size);
        std::size_t psa_ct_len = 0;
        ASSERT_EQ(RealPsaBackend::asymmetric_encrypt(
            psa_enc_id, RealPsaBackend::alg_rsa_oaep(),
            pt_arr.data(), pt_arr.size(), nullptr, 0,
            psa_ct.data(), psa_ct.size(), &psa_ct_len), RealPsaBackend::ok)
            << label << " PSA encrypt failed";
        (void)RealPsaBackend::destroy_key(psa_enc_id);

        // ARM decrypt with private key.
        auto arm_dec_attrs = NativeAsmBackend::make_rsa_oaep_decrypt_attrs(key_bits);
        NativeAsmBackend::KeyId arm_dec_id = NativeAsmBackend::null_key_id();
        ASSERT_EQ(NativeAsmBackend::import_key(
            &arm_dec_attrs, priv_der.data(), priv_der.size(), &arm_dec_id), NativeAsmBackend::ok)
            << label << " ARM private key import failed";

        const std::size_t pt_buf_size = NativeAsmBackend::rsa_oaep_decrypt_output_size(key_bits);
        SecureBuffer arm_pt(pt_buf_size);
        std::size_t arm_pt_len = 0;
        ASSERT_EQ(NativeAsmBackend::asymmetric_decrypt(
            arm_dec_id, NativeAsmBackend::alg_rsa_oaep(),
            psa_ct.data(), psa_ct_len, nullptr, 0,
            arm_pt.data(), arm_pt.size(), &arm_pt_len), NativeAsmBackend::ok)
            << label << " ARM decrypt failed (PSA→ARM)";
        (void)NativeAsmBackend::destroy_key(arm_dec_id);

        ASSERT_EQ(arm_pt_len, pt_arr.size());
        for (std::size_t i = 0; i < pt_arr.size(); ++i) {
            // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
            EXPECT_EQ(arm_pt[i], pt_arr[i]) << label << " PSA→ARM: mismatch at byte " << i;
        }
    }

    // ---- ARM encrypts, PSA decrypts -------------------------------------
    {
        const auto pt_arr = make_test_bytes<64>(0x62U); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)

        // ARM encrypt with public key.
        auto arm_enc_attrs = NativeAsmBackend::make_rsa_oaep_encrypt_attrs(key_bits);
        NativeAsmBackend::KeyId arm_enc_id = NativeAsmBackend::null_key_id();
        ASSERT_EQ(NativeAsmBackend::import_key(
            &arm_enc_attrs, pub_der.data(), pub_der.size(), &arm_enc_id), NativeAsmBackend::ok)
            << label << " ARM public key import failed";

        const std::size_t ct_buf_size = NativeAsmBackend::rsa_oaep_encrypt_output_size(key_bits);
        SecureBuffer arm_ct(ct_buf_size);
        std::size_t arm_ct_len = 0;
        ASSERT_EQ(NativeAsmBackend::asymmetric_encrypt(
            arm_enc_id, NativeAsmBackend::alg_rsa_oaep(),
            pt_arr.data(), pt_arr.size(), nullptr, 0,
            arm_ct.data(), arm_ct.size(), &arm_ct_len), NativeAsmBackend::ok)
            << label << " ARM encrypt failed";
        (void)NativeAsmBackend::destroy_key(arm_enc_id);

        // PSA decrypt with private key.
        auto psa_dec_attrs = RealPsaBackend::make_rsa_oaep_decrypt_attrs(key_bits);
        RealPsaBackend::KeyId psa_dec_id = RealPsaBackend::null_key_id();
        ASSERT_EQ(RealPsaBackend::import_key(
            &psa_dec_attrs, priv_der.data(), priv_der.size(), &psa_dec_id), RealPsaBackend::ok)
            << label << " PSA private key import failed";

        const std::size_t pt_buf_size = RealPsaBackend::rsa_oaep_decrypt_output_size(key_bits);
        SecureBuffer psa_pt(pt_buf_size);
        std::size_t psa_pt_len = 0;
        ASSERT_EQ(RealPsaBackend::asymmetric_decrypt(
            psa_dec_id, RealPsaBackend::alg_rsa_oaep(),
            arm_ct.data(), arm_ct_len, nullptr, 0,
            psa_pt.data(), psa_pt.size(), &psa_pt_len), RealPsaBackend::ok)
            << label << " PSA decrypt failed (ARM→PSA)";
        (void)RealPsaBackend::destroy_key(psa_dec_id);

        ASSERT_EQ(psa_pt_len, pt_arr.size());
        for (std::size_t i = 0; i < pt_arr.size(); ++i) {
            // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
            EXPECT_EQ(psa_pt[i], pt_arr[i]) << label << " ARM→PSA: mismatch at byte " << i;
        }
    }
}

template<RsaKeyBits KB>
static void run_rsa_pss_cross_verify_test(const char* label) {
    constexpr std::size_t key_bits = static_cast<std::size_t>(static_cast<std::uint16_t>(KB));

    const auto kp = generate_rsa_key_impl<KB, RealPsaBackend>();
    ASSERT_TRUE(kp.has_value()) << label << " RSA keygen failed";

    const auto& priv_der = kp->private_key_der;
    const auto& pub_der  = kp->public_key_der;

    const auto msg = make_test_bytes<64>(0x63U); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    const std::size_t sig_buf_size = RealPsaBackend::rsa_pss_sign_output_size(key_bits);

    // ---- PSA signs, ARM verifies ----------------------------------------
    {
        auto psa_sign_attrs = RealPsaBackend::make_rsa_pss_sign_attrs(key_bits);
        RealPsaBackend::KeyId psa_sign_id = RealPsaBackend::null_key_id();
        ASSERT_EQ(RealPsaBackend::import_key(
            &psa_sign_attrs, priv_der.data(), priv_der.size(), &psa_sign_id), RealPsaBackend::ok)
            << label << " PSA private key import failed";

        SecureBuffer psa_sig(sig_buf_size);
        std::size_t psa_sig_len = 0;
        ASSERT_EQ(RealPsaBackend::sign_message(
            psa_sign_id, RealPsaBackend::alg_rsa_pss(),
            msg.data(), msg.size(),
            psa_sig.data(), psa_sig.size(), &psa_sig_len), RealPsaBackend::ok)
            << label << " PSA sign failed";
        (void)RealPsaBackend::destroy_key(psa_sign_id);

        // ARM verify with public key.
        auto arm_verify_attrs = NativeAsmBackend::make_rsa_pss_verify_attrs(key_bits);
        NativeAsmBackend::KeyId arm_verify_id = NativeAsmBackend::null_key_id();
        ASSERT_EQ(NativeAsmBackend::import_key(
            &arm_verify_attrs, pub_der.data(), pub_der.size(), &arm_verify_id), NativeAsmBackend::ok)
            << label << " ARM public key import failed";

        EXPECT_EQ(NativeAsmBackend::verify_message(
            arm_verify_id, NativeAsmBackend::alg_rsa_pss(),
            msg.data(), msg.size(),
            psa_sig.data(), psa_sig_len), NativeAsmBackend::ok)
            << label << " ARM rejected PSA-RSA-PSS signature";
        (void)NativeAsmBackend::destroy_key(arm_verify_id);
    }

    // ---- ARM signs, PSA verifies ----------------------------------------
    {
        auto arm_sign_attrs = NativeAsmBackend::make_rsa_pss_sign_attrs(key_bits);
        NativeAsmBackend::KeyId arm_sign_id = NativeAsmBackend::null_key_id();
        ASSERT_EQ(NativeAsmBackend::import_key(
            &arm_sign_attrs, priv_der.data(), priv_der.size(), &arm_sign_id), NativeAsmBackend::ok)
            << label << " ARM private key import failed";

        SecureBuffer arm_sig(sig_buf_size);
        std::size_t arm_sig_len = 0;
        ASSERT_EQ(NativeAsmBackend::sign_message(
            arm_sign_id, NativeAsmBackend::alg_rsa_pss(),
            msg.data(), msg.size(),
            arm_sig.data(), arm_sig.size(), &arm_sig_len), NativeAsmBackend::ok)
            << label << " ARM sign failed";
        (void)NativeAsmBackend::destroy_key(arm_sign_id);

        // PSA verify with public key.
        auto psa_verify_attrs = RealPsaBackend::make_rsa_pss_verify_attrs(key_bits);
        RealPsaBackend::KeyId psa_verify_id = RealPsaBackend::null_key_id();
        ASSERT_EQ(RealPsaBackend::import_key(
            &psa_verify_attrs, pub_der.data(), pub_der.size(), &psa_verify_id), RealPsaBackend::ok)
            << label << " PSA public key import failed";

        EXPECT_EQ(RealPsaBackend::verify_message(
            psa_verify_id, RealPsaBackend::alg_rsa_pss(),
            msg.data(), msg.size(),
            arm_sig.data(), arm_sig_len), RealPsaBackend::ok)
            << label << " PSA rejected ARM-RSA-PSS signature";
        (void)RealPsaBackend::destroy_key(psa_verify_id);
    }
}

TEST_F(CrossProviderRsaTests, RsaOaepCrossDecrypt_3072) {
    run_rsa_oaep_cross_decrypt_test<RsaKeyBits::Bits3072>("RSA-OAEP-3072");
}
TEST_F(CrossProviderRsaTests, RsaOaepCrossDecrypt_4096) {
    run_rsa_oaep_cross_decrypt_test<RsaKeyBits::Bits4096>("RSA-OAEP-4096");
}
TEST_F(CrossProviderRsaTests, RsaPssCrossVerify_3072) {
    run_rsa_pss_cross_verify_test<RsaKeyBits::Bits3072>("RSA-PSS-3072");
}
TEST_F(CrossProviderRsaTests, RsaPssCrossVerify_4096) {
    run_rsa_pss_cross_verify_test<RsaKeyBits::Bits4096>("RSA-PSS-4096");
}

#endif  // SAFE_CRYPTO_PROVIDER_IA_ASM || SAFE_CRYPTO_ARM_ASM_AVAILABLE
