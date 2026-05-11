// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <gtest/gtest.h>

#include "cli_test_runner.hpp"


namespace scli_test {

class AeadTests : public ::testing::Test {
protected:
    static auto scli() -> const std::string& {
        static const std::string path{SCLI_PATH};  // NOLINT(cppcoreguidelines-pro-bounds-array-to-pointer-decay,hicpp-no-array-decay)
        return path;
    }

    // Fixed 32-byte key for deterministic tests.
    static constexpr const char* kKey = "base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    // "hello world" base64-encoded.
    static constexpr const char* kPlain = "base64:aGVsbG8gd29ybGQ=";
};

TEST_F(AeadTests, AesGcmEncryptProducesOutput) {
    const auto r = run_scli(scli(),
        {"aead", "--algo", "aes256-gcm", "--op", "encrypt", "--key", kKey, "--input", kPlain});
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_FALSE(r.stdout_text.empty());
}

TEST_F(AeadTests, AesGcmRoundTrip) {
    const auto enc = run_scli(scli(),
        {"aead", "--algo", "aes256-gcm", "--op", "encrypt", "--key", kKey, "--input", kPlain});
    ASSERT_EQ(enc.exit_code, 0);

    const auto dec = run_scli(scli(),
        {"aead", "--algo", "aes256-gcm", "--op", "decrypt", "--key", kKey,
         "--input", "base64:" + enc.stdout_text});
    EXPECT_EQ(dec.exit_code, 0);
    // Decrypted output is base64("hello world") = "aGVsbG8gd29ybGQ=".
    EXPECT_EQ(dec.stdout_text, "aGVsbG8gd29ybGQ=");
}

TEST_F(AeadTests, AesGcmDecryptFailsWithWrongKey) {
    const auto enc = run_scli(scli(),
        {"aead", "--algo", "aes256-gcm", "--op", "encrypt", "--key", kKey, "--input", kPlain});
    ASSERT_EQ(enc.exit_code, 0);

    const std::string other_key = "base64:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
    const auto dec = run_scli(scli(),
        {"aead", "--algo", "aes256-gcm", "--op", "decrypt", "--key", other_key,
         "--input", "base64:" + enc.stdout_text});
    EXPECT_NE(dec.exit_code, 0);
}

TEST_F(AeadTests, AesGcmRoundTripWithAad) {
    const std::string aad = "base64:bXkgYWFk";  // "my aad"
    const auto enc = run_scli(scli(),
        {"aead", "--algo", "aes256-gcm", "--op", "encrypt", "--key", kKey,
         "--input", kPlain, "--aad", aad});
    ASSERT_EQ(enc.exit_code, 0);

    const auto dec = run_scli(scli(),
        {"aead", "--algo", "aes256-gcm", "--op", "decrypt", "--key", kKey,
         "--input", "base64:" + enc.stdout_text, "--aad", aad});
    EXPECT_EQ(dec.exit_code, 0);
    EXPECT_EQ(dec.stdout_text, "aGVsbG8gd29ybGQ=");
}

TEST_F(AeadTests, AesGcmDecryptFailsWithWrongAad) {
    const std::string aad = "base64:bXkgYWFk";  // "my aad"
    const auto enc = run_scli(scli(),
        {"aead", "--algo", "aes256-gcm", "--op", "encrypt", "--key", kKey,
         "--input", kPlain, "--aad", aad});
    ASSERT_EQ(enc.exit_code, 0);

    // Decrypt with different AAD — authentication must fail.
    const std::string wrong_aad = "base64:d3Jvbmcgb25l";  // "wrong one"
    const auto dec = run_scli(scli(),
        {"aead", "--algo", "aes256-gcm", "--op", "decrypt", "--key", kKey,
         "--input", "base64:" + enc.stdout_text, "--aad", wrong_aad});
    EXPECT_NE(dec.exit_code, 0);
}

TEST_F(AeadTests, ChaCha20RoundTrip) {
    const auto enc = run_scli(scli(),
        {"aead", "--algo", "chacha20-poly1305", "--op", "encrypt", "--key", kKey,
         "--input", kPlain});
    ASSERT_EQ(enc.exit_code, 0);

    const auto dec = run_scli(scli(),
        {"aead", "--algo", "chacha20-poly1305", "--op", "decrypt", "--key", kKey,
         "--input", "base64:" + enc.stdout_text});
    EXPECT_EQ(dec.exit_code, 0);
    EXPECT_EQ(dec.stdout_text, "aGVsbG8gd29ybGQ=");
}

TEST_F(AeadTests, UnknownAlgoExitsNonZero) {
    const auto r = run_scli(scli(),
        {"aead", "--algo", "blowfish", "--op", "encrypt", "--key", kKey, "--input", kPlain});
    EXPECT_NE(r.exit_code, 0);
}

TEST_F(AeadTests, WrongKeySizeExitsNonZero) {
    // 16-byte key (too short for aes256-gcm).
    const std::string short_key = "base64:AAAAAAAAAAAAAAAAAAAAAA==";
    const auto r = run_scli(scli(),
        {"aead", "--algo", "aes256-gcm", "--op", "encrypt", "--key", short_key, "--input", kPlain});
    EXPECT_NE(r.exit_code, 0);
}

}  // namespace scli_test
