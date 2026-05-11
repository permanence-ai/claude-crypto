// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <filesystem>
#include <string>

#include <gtest/gtest.h>

#include "cli_test_runner.hpp"


namespace scli_test {

#ifdef SAFE_CRYPTO_PROVIDER_OPENSSL

class SlhDsaTests : public ::testing::Test {
protected:
    static auto scli() -> const std::string& {
        static const std::string path{SCLI_PATH};  // NOLINT(cppcoreguidelines-pro-bounds-array-to-pointer-decay,hicpp-no-array-decay)
        return path;
    }

    void TearDown() override {
        for (const auto& p : tmp_files_) { std::filesystem::remove(p); }
    }

    auto tmp(const std::string& name) -> std::string {
        const std::string path = (std::filesystem::temp_directory_path() / name).string();
        tmp_files_.push_back(path);
        return path;
    }

    static constexpr const char* kMsg      = "base64:aGVsbG8gd29ybGQ=";  // "hello world"
    static constexpr const char* kOtherMsg = "base64:d3JvbmcgbXNn";       // "wrong msg"

private:
    std::vector<std::string> tmp_files_;
};


// ─── keygen ──────────────────────────────────────────────────────────────────

TEST_F(SlhDsaTests, KeygenSha2128sProducesKeys) {
    const std::string priv_path = tmp("slhdsa_128s_priv.bin");
    const std::string pub_path  = tmp("slhdsa_128s_pub.bin");
    const auto r = run_scli(scli(),
        {"slh-dsa", "keygen", "--variant", "sha2-128s", "--out-private", priv_path, "--out-public", pub_path});
    ASSERT_EQ(r.exit_code, 0);
    EXPECT_EQ(std::filesystem::file_size(priv_path), 64U);
    EXPECT_EQ(std::filesystem::file_size(pub_path),  32U);
}

TEST_F(SlhDsaTests, KeygenSha2128fProducesKeys) {
    const std::string priv_path = tmp("slhdsa_128f_priv.bin");
    const std::string pub_path  = tmp("slhdsa_128f_pub.bin");
    const auto r = run_scli(scli(),
        {"slh-dsa", "keygen", "--variant", "sha2-128f", "--out-private", priv_path, "--out-public", pub_path});
    ASSERT_EQ(r.exit_code, 0);
    EXPECT_EQ(std::filesystem::file_size(priv_path), 64U);
    EXPECT_EQ(std::filesystem::file_size(pub_path),  32U);
}

TEST_F(SlhDsaTests, KeygenUnknownVariantExitsNonZero) {
    const auto r = run_scli(scli(),
        {"slh-dsa", "keygen", "--variant", "sha2-999s", "--out-private", "/dev/null", "--out-public", "/dev/null"});
    EXPECT_NE(r.exit_code, 0);
}


// ─── sign / verify round-trip ────────────────────────────────────────────────
// Use sha2-128f (fast variant) to keep test time reasonable.

TEST_F(SlhDsaTests, RoundTripSha2128f) {
    const std::string priv_path = tmp("rt128f_priv.bin");
    const std::string pub_path  = tmp("rt128f_pub.bin");
    const std::string sig_path  = tmp("rt128f_sig.bin");

    ASSERT_EQ(run_scli(scli(),
        {"slh-dsa", "keygen", "--variant", "sha2-128f", "--out-private", priv_path, "--out-public", pub_path}
    ).exit_code, 0);

    ASSERT_EQ(run_scli(scli(),
        {"slh-dsa", "sign", "--variant", "sha2-128f", "--key", priv_path,
         "--input", std::string(kMsg), "--output", sig_path}
    ).exit_code, 0);

    EXPECT_EQ(std::filesystem::file_size(sig_path), 17088U);

    EXPECT_EQ(run_scli(scli(),
        {"slh-dsa", "verify", "--variant", "sha2-128f", "--key", pub_path,
         "--input", std::string(kMsg), "--signature", sig_path}
    ).exit_code, 0);
}

TEST_F(SlhDsaTests, RoundTripSha2128s) {
    const std::string priv_path = tmp("rt128s_priv.bin");
    const std::string pub_path  = tmp("rt128s_pub.bin");
    const std::string sig_path  = tmp("rt128s_sig.bin");

    ASSERT_EQ(run_scli(scli(),
        {"slh-dsa", "keygen", "--variant", "sha2-128s", "--out-private", priv_path, "--out-public", pub_path}
    ).exit_code, 0);

    ASSERT_EQ(run_scli(scli(),
        {"slh-dsa", "sign", "--variant", "sha2-128s", "--key", priv_path,
         "--input", std::string(kMsg), "--output", sig_path}
    ).exit_code, 0);

    EXPECT_EQ(std::filesystem::file_size(sig_path), 7856U);

    EXPECT_EQ(run_scli(scli(),
        {"slh-dsa", "verify", "--variant", "sha2-128s", "--key", pub_path,
         "--input", std::string(kMsg), "--signature", sig_path}
    ).exit_code, 0);
}

TEST_F(SlhDsaTests, VerifyWrongMessageExitsNonZero) {
    const std::string priv_path = tmp("wm_priv.bin");
    const std::string pub_path  = tmp("wm_pub.bin");
    const std::string sig_path  = tmp("wm_sig.bin");

    ASSERT_EQ(run_scli(scli(),
        {"slh-dsa", "keygen", "--variant", "sha2-128f", "--out-private", priv_path, "--out-public", pub_path}
    ).exit_code, 0);
    ASSERT_EQ(run_scli(scli(),
        {"slh-dsa", "sign", "--variant", "sha2-128f", "--key", priv_path,
         "--input", std::string(kMsg), "--output", sig_path}
    ).exit_code, 0);

    EXPECT_NE(run_scli(scli(),
        {"slh-dsa", "verify", "--variant", "sha2-128f", "--key", pub_path,
         "--input", std::string(kOtherMsg), "--signature", sig_path}
    ).exit_code, 0);
}

TEST_F(SlhDsaTests, VerifyWrongKeyExitsNonZero) {
    const std::string priv1_path = tmp("wk_priv1.bin");
    const std::string pub1_path  = tmp("wk_pub1.bin");
    const std::string priv2_path = tmp("wk_priv2.bin");
    const std::string pub2_path  = tmp("wk_pub2.bin");
    const std::string sig_path   = tmp("wk_sig.bin");

    ASSERT_EQ(run_scli(scli(),
        {"slh-dsa", "keygen", "--variant", "sha2-128f", "--out-private", priv1_path, "--out-public", pub1_path}
    ).exit_code, 0);
    ASSERT_EQ(run_scli(scli(),
        {"slh-dsa", "keygen", "--variant", "sha2-128f", "--out-private", priv2_path, "--out-public", pub2_path}
    ).exit_code, 0);
    ASSERT_EQ(run_scli(scli(),
        {"slh-dsa", "sign", "--variant", "sha2-128f", "--key", priv1_path,
         "--input", std::string(kMsg), "--output", sig_path}
    ).exit_code, 0);

    EXPECT_NE(run_scli(scli(),
        {"slh-dsa", "verify", "--variant", "sha2-128f", "--key", pub2_path,
         "--input", std::string(kMsg), "--signature", sig_path}
    ).exit_code, 0);
}

TEST_F(SlhDsaTests, SignOutputToBase64Stdout) {
    const std::string priv_path = tmp("b64_priv.bin");
    const std::string pub_path  = tmp("b64_pub.bin");

    ASSERT_EQ(run_scli(scli(),
        {"slh-dsa", "keygen", "--variant", "sha2-128f", "--out-private", priv_path, "--out-public", pub_path}
    ).exit_code, 0);

    const auto r = run_scli(scli(),
        {"slh-dsa", "sign", "--variant", "sha2-128f", "--key", priv_path, "--input", std::string(kMsg)});
    ASSERT_EQ(r.exit_code, 0);
    // 17088 bytes → base64 is larger
    EXPECT_GT(r.stdout_text.size(), 20000U);
}

#endif  // SAFE_CRYPTO_PROVIDER_OPENSSL

}  // namespace scli_test
