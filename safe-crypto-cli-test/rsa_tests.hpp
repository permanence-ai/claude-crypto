// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <filesystem>
#include <string>

#include <gtest/gtest.h>

#include "cli_test_runner.hpp"


namespace scli_test {

// All RSA tests share one key pair generated in SetUpTestSuite to avoid
// paying the Miller-Rabin keygen cost once per test.
class RsaTests : public ::testing::Test {
protected:
    static auto scli() -> const std::string& {
        static const std::string path{SCLI_PATH};  // NOLINT(cppcoreguidelines-pro-bounds-array-to-pointer-decay,hicpp-no-array-decay)
        return path;
    }

    static void SetUpTestSuite() {
        priv_path_ = (std::filesystem::temp_directory_path() / "rsa_test_priv.der").string();
        pub_path_  = (std::filesystem::temp_directory_path() / "rsa_test_pub.der").string();
        const auto r = run_scli(scli(),
            "rsa keygen --bits 3072"
            " --out-private " + priv_path_ +
            " --out-public "  + pub_path_);
        keygen_ok_ = (r.exit_code == 0);
    }

    static void TearDownTestSuite() {
        std::filesystem::remove(priv_path_);
        std::filesystem::remove(pub_path_);
    }

    // NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
    static std::string priv_path_;
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
    static std::string pub_path_;
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
    static bool keygen_ok_;

    // "hello world" base64-encoded.
    static constexpr const char* kMsg = "base64:aGVsbG8gd29ybGQ=";
    // A different message.
    static constexpr const char* kOtherMsg = "base64:d3JvbmcgbXNn";
};

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
std::string RsaTests::priv_path_;
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
std::string RsaTests::pub_path_;
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
bool RsaTests::keygen_ok_ = false;


TEST_F(RsaTests, KeygenProducesFiles) {
    ASSERT_TRUE(keygen_ok_);
    EXPECT_GT(std::filesystem::file_size(priv_path_), 0U);
    EXPECT_GT(std::filesystem::file_size(pub_path_),  0U);
}

TEST_F(RsaTests, OaepRoundTrip) {
    ASSERT_TRUE(keygen_ok_);
    const auto enc = run_scli(scli(),
        "rsa oaep-encrypt --bits 3072 --key " + pub_path_ + " --input " + kMsg);
    ASSERT_EQ(enc.exit_code, 0);
    ASSERT_FALSE(enc.stdout_text.empty());

    const auto dec = run_scli(scli(),
        "rsa oaep-decrypt --bits 3072 --key " + priv_path_ +
        " --input base64:" + enc.stdout_text);
    EXPECT_EQ(dec.exit_code, 0);
    // Decrypted plaintext is base64("hello world").
    EXPECT_EQ(dec.stdout_text, "aGVsbG8gd29ybGQ=");
}

TEST_F(RsaTests, OaepDecryptFailsWithWrongKey) {
    ASSERT_TRUE(keygen_ok_);

    // Generate a second key pair for the wrong-key test.
    const std::string priv2 = (std::filesystem::temp_directory_path() / "rsa_wrong_priv.der").string();
    const std::string pub2  = (std::filesystem::temp_directory_path() / "rsa_wrong_pub.der").string();
    const auto kg2 = run_scli(scli(),
        "rsa keygen --bits 3072 --out-private " + priv2 + " --out-public " + pub2);
    ASSERT_EQ(kg2.exit_code, 0);

    const auto enc = run_scli(scli(),
        "rsa oaep-encrypt --bits 3072 --key " + pub_path_ + " --input " + kMsg);
    ASSERT_EQ(enc.exit_code, 0);

    // Decrypt with key2 — must fail.
    const auto dec = run_scli(scli(),
        "rsa oaep-decrypt --bits 3072 --key " + priv2 +
        " --input base64:" + enc.stdout_text);
    EXPECT_NE(dec.exit_code, 0);

    std::filesystem::remove(priv2);
    std::filesystem::remove(pub2);
}

TEST_F(RsaTests, OaepRoundTripWithLabel) {
    ASSERT_TRUE(keygen_ok_);
    const std::string label = "base64:bXkgbGFiZWw=";  // "my label"

    const auto enc = run_scli(scli(),
        "rsa oaep-encrypt --bits 3072 --key " + pub_path_ +
        " --input " + kMsg + " --label " + label);
    ASSERT_EQ(enc.exit_code, 0);

    const auto dec = run_scli(scli(),
        "rsa oaep-decrypt --bits 3072 --key " + priv_path_ +
        " --input base64:" + enc.stdout_text + " --label " + label);
    EXPECT_EQ(dec.exit_code, 0);
    EXPECT_EQ(dec.stdout_text, "aGVsbG8gd29ybGQ=");
}

TEST_F(RsaTests, OaepDecryptFailsWithWrongLabel) {
    ASSERT_TRUE(keygen_ok_);
    const std::string label      = "base64:bXkgbGFiZWw=";   // "my label"
    const std::string wrong_label = "base64:d3JvbmcgbGFiZWw=";  // "wrong label"

    const auto enc = run_scli(scli(),
        "rsa oaep-encrypt --bits 3072 --key " + pub_path_ +
        " --input " + kMsg + " --label " + label);
    ASSERT_EQ(enc.exit_code, 0);

    const auto dec = run_scli(scli(),
        "rsa oaep-decrypt --bits 3072 --key " + priv_path_ +
        " --input base64:" + enc.stdout_text + " --label " + wrong_label);
    EXPECT_NE(dec.exit_code, 0);
}

TEST_F(RsaTests, PssSignVerifyRoundTrip) {
    ASSERT_TRUE(keygen_ok_);
    const auto sig = run_scli(scli(),
        "rsa pss-sign --bits 3072 --key " + priv_path_ + " --input " + kMsg);
    ASSERT_EQ(sig.exit_code, 0);
    ASSERT_FALSE(sig.stdout_text.empty());

    const auto verify = run_scli(scli(),
        "rsa pss-verify --bits 3072 --key " + pub_path_ +
        " --input " + kMsg + " --signature base64:" + sig.stdout_text);
    EXPECT_EQ(verify.exit_code, 0);
}

TEST_F(RsaTests, PssVerifyFailsWithWrongMessage) {
    ASSERT_TRUE(keygen_ok_);
    const auto sig = run_scli(scli(),
        "rsa pss-sign --bits 3072 --key " + priv_path_ + " --input " + kMsg);
    ASSERT_EQ(sig.exit_code, 0);

    const auto verify = run_scli(scli(),
        "rsa pss-verify --bits 3072 --key " + pub_path_ +
        " --input " + kOtherMsg + " --signature base64:" + sig.stdout_text);
    EXPECT_NE(verify.exit_code, 0);
}

TEST_F(RsaTests, PssSignatureToFile) {
    ASSERT_TRUE(keygen_ok_);
    const std::string sig_path = (std::filesystem::temp_directory_path() / "rsa_sig.bin").string();

    const auto sig = run_scli(scli(),
        "rsa pss-sign --bits 3072 --key " + priv_path_ +
        " --input " + kMsg + " --output " + sig_path);
    ASSERT_EQ(sig.exit_code, 0);
    // 3072-bit RSA-PSS signature is 384 bytes.
    EXPECT_EQ(std::filesystem::file_size(sig_path), 384U);

    const auto verify = run_scli(scli(),
        "rsa pss-verify --bits 3072 --key " + pub_path_ +
        " --input " + kMsg + " --signature " + sig_path);
    EXPECT_EQ(verify.exit_code, 0);

    std::filesystem::remove(sig_path);
}

TEST_F(RsaTests, UnknownBitsExitsNonZero) {
    const auto r = run_scli(scli(), "rsa keygen --bits 2048");
    EXPECT_NE(r.exit_code, 0);
}

}  // namespace scli_test
