// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdlib>
#include <filesystem>
#include <string>
#include <utility>

#include <gtest/gtest.h>

#include "cli_test_runner.hpp"


namespace scli_test {

class EcdsaTests : public ::testing::Test {
protected:
    static auto scli() -> const std::string& {
        static const std::string path{SCLI_PATH};  // NOLINT(cppcoreguidelines-pro-bounds-array-to-pointer-decay,hicpp-no-array-decay)
        return path;
    }

    // "hello world" base64-encoded.
    static constexpr const char* kMsg = "base64:aGVsbG8gd29ybGQ=";
    // A different message to test rejection.
    static constexpr const char* kOtherMsg = "base64:d3JvbmcgbXNn";
};


// Helper: generate a key pair to temp files, return {priv_path, pub_path}.
// Caller must delete the files.
[[nodiscard]]
static auto keygen_to_files(const std::string& scli_path, const std::string& curve)
    -> std::pair<std::string, std::string>
{
    const std::string tmp = std::filesystem::temp_directory_path().string();
    const std::string priv_path = tmp + "/scli_test_priv_" + curve + ".der";
    const std::string pub_path  = tmp + "/scli_test_pub_"  + curve + ".der";

    const auto r = run_scli(scli_path,
        {"ecdsa", "keygen", "--curve", curve, "--out-private", priv_path, "--out-public", pub_path});

    if (r.exit_code != 0) { return {"", ""}; }
    return {priv_path, pub_path};
}


TEST_F(EcdsaTests, KeygenP256ProducesFiles) {
    const std::string tmp = std::filesystem::temp_directory_path().string();
    const std::string priv_path = tmp + "/scli_test_keygen_priv.der";
    const std::string pub_path  = tmp + "/scli_test_keygen_pub.der";

    const auto r = run_scli(scli(),
        {"ecdsa", "keygen", "--curve", "p256", "--out-private", priv_path, "--out-public", pub_path});
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_TRUE(std::filesystem::exists(priv_path));
    EXPECT_TRUE(std::filesystem::exists(pub_path));
    EXPECT_GT(std::filesystem::file_size(priv_path), 0U);
    EXPECT_GT(std::filesystem::file_size(pub_path), 0U);

    std::filesystem::remove(priv_path);
    std::filesystem::remove(pub_path);
}

TEST_F(EcdsaTests, KeygenP256ProducesBase64Output) {
    // keygen with no --out-private/--out-public prints both keys to stdout (base64).
    const auto r = run_scli(scli(), {"ecdsa", "keygen", "--curve", "p256"});
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_FALSE(r.stdout_text.empty());
}

TEST_F(EcdsaTests, RoundTripP256) {
    auto [priv, pub] = keygen_to_files(scli(), "p256");
    ASSERT_FALSE(priv.empty());

    const auto sig = run_scli(scli(),
        {"ecdsa", "sign", "--curve", "p256", "--key", priv, "--input", kMsg});
    ASSERT_EQ(sig.exit_code, 0);
    ASSERT_FALSE(sig.stdout_text.empty());

    const auto verify = run_scli(scli(),
        {"ecdsa", "verify", "--curve", "p256", "--key", pub,
         "--input", kMsg, "--signature", "base64:" + sig.stdout_text});
    EXPECT_EQ(verify.exit_code, 0);

    std::filesystem::remove(priv);
    std::filesystem::remove(pub);
}

TEST_F(EcdsaTests, RoundTripP384) {
    auto [priv, pub] = keygen_to_files(scli(), "p384");
    ASSERT_FALSE(priv.empty());

    const auto sig = run_scli(scli(),
        {"ecdsa", "sign", "--curve", "p384", "--key", priv, "--input", kMsg});
    ASSERT_EQ(sig.exit_code, 0);

    const auto verify = run_scli(scli(),
        {"ecdsa", "verify", "--curve", "p384", "--key", pub,
         "--input", kMsg, "--signature", "base64:" + sig.stdout_text});
    EXPECT_EQ(verify.exit_code, 0);

    std::filesystem::remove(priv);
    std::filesystem::remove(pub);
}

TEST_F(EcdsaTests, RoundTripP521) {
    auto [priv, pub] = keygen_to_files(scli(), "p521");
    ASSERT_FALSE(priv.empty());

    const auto sig = run_scli(scli(),
        {"ecdsa", "sign", "--curve", "p521", "--key", priv, "--input", kMsg});
    ASSERT_EQ(sig.exit_code, 0);

    const auto verify = run_scli(scli(),
        {"ecdsa", "verify", "--curve", "p521", "--key", pub,
         "--input", kMsg, "--signature", "base64:" + sig.stdout_text});
    EXPECT_EQ(verify.exit_code, 0);

    std::filesystem::remove(priv);
    std::filesystem::remove(pub);
}

TEST_F(EcdsaTests, VerifyFailsWithWrongMessage) {
    auto [priv, pub] = keygen_to_files(scli(), "p256");
    ASSERT_FALSE(priv.empty());

    const auto sig = run_scli(scli(),
        {"ecdsa", "sign", "--curve", "p256", "--key", priv, "--input", kMsg});
    ASSERT_EQ(sig.exit_code, 0);

    const auto verify = run_scli(scli(),
        {"ecdsa", "verify", "--curve", "p256", "--key", pub,
         "--input", kOtherMsg, "--signature", "base64:" + sig.stdout_text});
    EXPECT_NE(verify.exit_code, 0);

    std::filesystem::remove(priv);
    std::filesystem::remove(pub);
}

TEST_F(EcdsaTests, VerifyFailsWithWrongKey) {
    auto [priv1, pub1] = keygen_to_files(scli(), "p256");
    ASSERT_FALSE(priv1.empty());

    const std::string tmp = std::filesystem::temp_directory_path().string();
    const std::string priv2 = tmp + "/scli_test_priv2.der";
    const std::string pub2  = tmp + "/scli_test_pub2.der";
    const auto kg2 = run_scli(scli(),
        {"ecdsa", "keygen", "--curve", "p256", "--out-private", priv2, "--out-public", pub2});
    ASSERT_EQ(kg2.exit_code, 0);

    const auto sig = run_scli(scli(),
        {"ecdsa", "sign", "--curve", "p256", "--key", priv1, "--input", kMsg});
    ASSERT_EQ(sig.exit_code, 0);

    // Verify sig from key1 against pub2.
    const auto verify = run_scli(scli(),
        {"ecdsa", "verify", "--curve", "p256", "--key", pub2,
         "--input", kMsg, "--signature", "base64:" + sig.stdout_text});
    EXPECT_NE(verify.exit_code, 0);

    std::filesystem::remove(priv1);
    std::filesystem::remove(pub1);
    std::filesystem::remove(priv2);
    std::filesystem::remove(pub2);
}

TEST_F(EcdsaTests, RepeatedSignaturesVerify) {
    auto [priv, pub] = keygen_to_files(scli(), "p256");
    ASSERT_FALSE(priv.empty());

    const auto sig1 = run_scli(scli(),
        {"ecdsa", "sign", "--curve", "p256", "--key", priv, "--input", kMsg});
    const auto sig2 = run_scli(scli(),
        {"ecdsa", "sign", "--curve", "p256", "--key", priv, "--input", kMsg});
    ASSERT_EQ(sig1.exit_code, 0);
    ASSERT_EQ(sig2.exit_code, 0);

    const auto verify1 = run_scli(scli(),
        {"ecdsa", "verify", "--curve", "p256", "--key", pub,
         "--input", kMsg, "--signature", "base64:" + sig1.stdout_text});
    const auto verify2 = run_scli(scli(),
        {"ecdsa", "verify", "--curve", "p256", "--key", pub,
         "--input", kMsg, "--signature", "base64:" + sig2.stdout_text});
    EXPECT_EQ(verify1.exit_code, 0);
    EXPECT_EQ(verify2.exit_code, 0);

    std::filesystem::remove(priv);
    std::filesystem::remove(pub);
}

TEST_F(EcdsaTests, UnknownCurveExitsNonZero) {
    const auto r = run_scli(scli(), {"ecdsa", "keygen", "--curve", "secp256k1"});
    EXPECT_NE(r.exit_code, 0);
}

}  // namespace scli_test
