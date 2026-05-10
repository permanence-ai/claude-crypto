// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <filesystem>
#include <string>

#include <gtest/gtest.h>

#include "cli_test_runner.hpp"


namespace scli_test {

#ifdef SAFE_CRYPTO_PQC_LIBOQS

class MlDsaTests : public ::testing::Test {
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

TEST_F(MlDsaTests, KeygenDsa44ProducesKeys) {
    const std::string priv_path = tmp("mldsa_44_priv.bin");
    const std::string pub_path  = tmp("mldsa_44_pub.bin");
    const auto r = run_scli(scli(),
        "ml-dsa keygen --variant 44 --out-private " + priv_path + " --out-public " + pub_path);
    ASSERT_EQ(r.exit_code, 0);
    EXPECT_EQ(std::filesystem::file_size(priv_path), 2560U);
    EXPECT_EQ(std::filesystem::file_size(pub_path),  1312U);
}

TEST_F(MlDsaTests, KeygenDsa65ProducesKeys) {
    const std::string priv_path = tmp("mldsa_65_priv.bin");
    const std::string pub_path  = tmp("mldsa_65_pub.bin");
    const auto r = run_scli(scli(),
        "ml-dsa keygen --variant 65 --out-private " + priv_path + " --out-public " + pub_path);
    ASSERT_EQ(r.exit_code, 0);
    EXPECT_EQ(std::filesystem::file_size(priv_path), 4032U);
    EXPECT_EQ(std::filesystem::file_size(pub_path),  1952U);
}

TEST_F(MlDsaTests, KeygenDsa87ProducesKeys) {
    const std::string priv_path = tmp("mldsa_87_priv.bin");
    const std::string pub_path  = tmp("mldsa_87_pub.bin");
    const auto r = run_scli(scli(),
        "ml-dsa keygen --variant 87 --out-private " + priv_path + " --out-public " + pub_path);
    ASSERT_EQ(r.exit_code, 0);
    EXPECT_EQ(std::filesystem::file_size(priv_path), 4896U);
    EXPECT_EQ(std::filesystem::file_size(pub_path),  2592U);
}

TEST_F(MlDsaTests, KeygenUnknownVariantExitsNonZero) {
    const auto r = run_scli(scli(),
        "ml-dsa keygen --variant 99 --out-private /dev/null --out-public /dev/null");
    EXPECT_NE(r.exit_code, 0);
}


// ─── sign / verify round-trip ────────────────────────────────────────────────

TEST_F(MlDsaTests, RoundTripDsa44) {
    const std::string priv_path = tmp("rt44_priv.bin");
    const std::string pub_path  = tmp("rt44_pub.bin");
    const std::string sig_path  = tmp("rt44_sig.bin");

    ASSERT_EQ(run_scli(scli(),
        "ml-dsa keygen --variant 44 --out-private " + priv_path + " --out-public " + pub_path
    ).exit_code, 0);

    ASSERT_EQ(run_scli(scli(),
        "ml-dsa sign --variant 44 --key " + priv_path +
        " --input " + std::string(kMsg) + " --output " + sig_path
    ).exit_code, 0);

    EXPECT_EQ(std::filesystem::file_size(sig_path), 2420U);

    EXPECT_EQ(run_scli(scli(),
        "ml-dsa verify --variant 44 --key " + pub_path +
        " --input " + std::string(kMsg) + " --signature " + sig_path
    ).exit_code, 0);
}

TEST_F(MlDsaTests, RoundTripDsa87) {
    const std::string priv_path = tmp("rt87_priv.bin");
    const std::string pub_path  = tmp("rt87_pub.bin");
    const std::string sig_path  = tmp("rt87_sig.bin");

    ASSERT_EQ(run_scli(scli(),
        "ml-dsa keygen --variant 87 --out-private " + priv_path + " --out-public " + pub_path
    ).exit_code, 0);

    ASSERT_EQ(run_scli(scli(),
        "ml-dsa sign --variant 87 --key " + priv_path +
        " --input " + std::string(kMsg) + " --output " + sig_path
    ).exit_code, 0);

    EXPECT_EQ(std::filesystem::file_size(sig_path), 4627U);

    EXPECT_EQ(run_scli(scli(),
        "ml-dsa verify --variant 87 --key " + pub_path +
        " --input " + std::string(kMsg) + " --signature " + sig_path
    ).exit_code, 0);
}

TEST_F(MlDsaTests, VerifyWrongMessageExitsNonZero) {
    const std::string priv_path = tmp("wm_priv.bin");
    const std::string pub_path  = tmp("wm_pub.bin");
    const std::string sig_path  = tmp("wm_sig.bin");

    ASSERT_EQ(run_scli(scli(),
        "ml-dsa keygen --variant 44 --out-private " + priv_path + " --out-public " + pub_path
    ).exit_code, 0);
    ASSERT_EQ(run_scli(scli(),
        "ml-dsa sign --variant 44 --key " + priv_path +
        " --input " + std::string(kMsg) + " --output " + sig_path
    ).exit_code, 0);

    EXPECT_NE(run_scli(scli(),
        "ml-dsa verify --variant 44 --key " + pub_path +
        " --input " + std::string(kOtherMsg) + " --signature " + sig_path
    ).exit_code, 0);
}

TEST_F(MlDsaTests, VerifyWrongKeyExitsNonZero) {
    const std::string priv1_path = tmp("wk_priv1.bin");
    const std::string pub1_path  = tmp("wk_pub1.bin");
    const std::string priv2_path = tmp("wk_priv2.bin");
    const std::string pub2_path  = tmp("wk_pub2.bin");
    const std::string sig_path   = tmp("wk_sig.bin");

    ASSERT_EQ(run_scli(scli(),
        "ml-dsa keygen --variant 44 --out-private " + priv1_path + " --out-public " + pub1_path
    ).exit_code, 0);
    ASSERT_EQ(run_scli(scli(),
        "ml-dsa keygen --variant 44 --out-private " + priv2_path + " --out-public " + pub2_path
    ).exit_code, 0);
    ASSERT_EQ(run_scli(scli(),
        "ml-dsa sign --variant 44 --key " + priv1_path +
        " --input " + std::string(kMsg) + " --output " + sig_path
    ).exit_code, 0);

    EXPECT_NE(run_scli(scli(),
        "ml-dsa verify --variant 44 --key " + pub2_path +
        " --input " + std::string(kMsg) + " --signature " + sig_path
    ).exit_code, 0);
}

TEST_F(MlDsaTests, SignOutputToBase64Stdout) {
    const std::string priv_path = tmp("b64_priv.bin");
    const std::string pub_path  = tmp("b64_pub.bin");

    ASSERT_EQ(run_scli(scli(),
        "ml-dsa keygen --variant 44 --out-private " + priv_path + " --out-public " + pub_path
    ).exit_code, 0);

    const auto r = run_scli(scli(),
        "ml-dsa sign --variant 44 --key " + priv_path + " --input " + std::string(kMsg));
    ASSERT_EQ(r.exit_code, 0);
    // 2420 bytes → ceil(2420/3)*4 = 3228 base64 chars (no padding needed as 2420 % 3 = 2 → +2 padding)
    EXPECT_GT(r.stdout_text.size(), 3000U);
}

#endif  // SAFE_CRYPTO_PQC_LIBOQS

}  // namespace scli_test
