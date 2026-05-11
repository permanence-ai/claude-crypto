// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <filesystem>
#include <string>

#include <gtest/gtest.h>

#include "cli_test_runner.hpp"


namespace scli_test {

class KdfTests : public ::testing::Test {
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

    auto tmp_b64(const std::string& name, const std::string& b64) -> std::string {
        const std::string path = write_temp_file_b64(name, b64);
        tmp_files_.push_back(path);
        return path;
    }

    // 64 zero bytes base64-encoded — used as IKM in known-answer tests.
    // IKM must be >= 2 * output_length; 64 bytes covers output up to 32.
    static constexpr const char* kZero64B64 =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    // 48 zero bytes base64-encoded — used as SHA-384-length PRK for HKDF-Expand.
    static constexpr const char* kZero48B64 =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    // Known outputs from scli for zero inputs (SHA-384, PSA/MbedTLS backend).
    // Derive: 32-byte output, zero 64-byte IKM, no salt, no info.
    static constexpr const char* kDeriveZeroNoSaltNoInfo =
        "ulenYxQOSPZ1c9AIV9MiAryE3RitThoFI1EsknBQCv4=";
    // Derive: 32-byte output, zero 64-byte IKM, salt="salt", info="info".
    static constexpr const char* kDeriveZeroWithSaltInfo =
        "oo2cHefZaY/QhKs3c81TOA1cZ0SBC9i3eoCeeB/gj9Q=";
    // Expand: 32-byte output, zero 48-byte PRK, no info.
    static constexpr const char* kExpandZeroNoInfo =
        "h0BYosBJgslT5KW7T6MPthImz1svpWAXQel2dSoC3bg=";
    // Expand: 32-byte output, zero 48-byte PRK, info="info".
    static constexpr const char* kExpandZeroWithInfo =
        "YnL0ox8WmpZYqwlanOIp8VA0LrFf4fr3r5zSS5jUz9w=";

private:
    std::vector<std::string> tmp_files_;
};


// ─── derive ──────────────────────────────────────────────────────────────────

TEST_F(KdfTests, DeriveProducesCorrectLength) {
    const auto r = run_scli(scli(),
        {"kdf", "derive", "--length", "32", "--ikm", "base64:" + std::string(kZero64B64)});
    EXPECT_EQ(r.exit_code, 0);
    // 32 bytes → 44-char base64.
    EXPECT_EQ(r.stdout_text.size(), 44U);
}

TEST_F(KdfTests, DeriveKnownAnswer_NoSaltNoInfo) {
    const auto r = run_scli(scli(),
        {"kdf", "derive", "--length", "32", "--ikm", "base64:" + std::string(kZero64B64)});
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_EQ(r.stdout_text, kDeriveZeroNoSaltNoInfo);
}

TEST_F(KdfTests, DeriveKnownAnswer_WithSaltAndInfo) {
    const auto r = run_scli(scli(),
        {"kdf", "derive", "--length", "32",
         "--ikm", "base64:" + std::string(kZero64B64),
         "--salt", "base64:c2FsdA==",    // "salt"
         "--info", "base64:aW5mbw=="});  // "info"
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_EQ(r.stdout_text, kDeriveZeroWithSaltInfo);
}

TEST_F(KdfTests, DeriveSaltChangesOutput) {
    const auto without = run_scli(scli(),
        {"kdf", "derive", "--length", "32", "--ikm", "base64:" + std::string(kZero64B64)});
    const auto with_salt = run_scli(scli(),
        {"kdf", "derive", "--length", "32",
         "--ikm", "base64:" + std::string(kZero64B64),
         "--salt", "base64:c2FsdA=="});
    ASSERT_EQ(without.exit_code, 0);
    ASSERT_EQ(with_salt.exit_code, 0);
    EXPECT_NE(without.stdout_text, with_salt.stdout_text);
}

TEST_F(KdfTests, DeriveInfoChangesOutput) {
    const auto without = run_scli(scli(),
        {"kdf", "derive", "--length", "32", "--ikm", "base64:" + std::string(kZero64B64)});
    const auto with_info = run_scli(scli(),
        {"kdf", "derive", "--length", "32",
         "--ikm", "base64:" + std::string(kZero64B64),
         "--info", "base64:aW5mbw=="});
    ASSERT_EQ(without.exit_code, 0);
    ASSERT_EQ(with_info.exit_code, 0);
    EXPECT_NE(without.stdout_text, with_info.stdout_text);
}

TEST_F(KdfTests, DeriveOutputToFile) {
    const std::string out_path = tmp("kdf_derive_out.bin");
    const auto r = run_scli(scli(),
        {"kdf", "derive", "--length", "32",
         "--ikm", "base64:" + std::string(kZero64B64),
         "--output", out_path});
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_EQ(std::filesystem::file_size(out_path), 32U);
}

TEST_F(KdfTests, DeriveWithoutIkmSavesGeneratedIkm) {
    // When --ikm is omitted the CLI generates random IKM and writes it to
    // --out-ikm.  Re-running with that same IKM must reproduce the same output.
    const std::string ikm_path = tmp("kdf_gen_ikm.bin");
    const auto first = run_scli(scli(),
        {"kdf", "derive", "--length", "32", "--out-ikm", ikm_path});
    ASSERT_EQ(first.exit_code, 0);
    ASSERT_EQ(std::filesystem::file_size(ikm_path), 64U);  // 2 * 32

    // Reproduce using the saved IKM.
    const auto ikm_bytes = read_file_bytes(ikm_path);
    std::string ikm_b64;
    {
        static constexpr const char* kAlpha =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        uint32_t acc = 0;
        int      bits = 0;
        for (const uint8_t byte : ikm_bytes) {
            acc  = (acc << 8U) | byte;
            bits += 8;
            while (bits >= 6) {
                bits -= 6;
                ikm_b64 += kAlpha[(acc >> static_cast<unsigned>(bits)) & 0x3FU];
            }
        }
        if (bits > 0) {
            ikm_b64 += kAlpha[(acc << static_cast<unsigned>(6 - bits)) & 0x3FU];
        }
        while (ikm_b64.size() % 4 != 0) { ikm_b64 += '='; }
    }

    const auto second = run_scli(scli(),
        {"kdf", "derive", "--length", "32", "--ikm", "base64:" + ikm_b64});
    ASSERT_EQ(second.exit_code, 0);
    EXPECT_EQ(first.stdout_text, second.stdout_text);
}

TEST_F(KdfTests, DeriveZeroLengthExitsNonZero) {
    const auto r = run_scli(scli(),
        {"kdf", "derive", "--length", "0", "--ikm", "base64:" + std::string(kZero64B64)});
    EXPECT_NE(r.exit_code, 0);
}

TEST_F(KdfTests, DeriveIkmTooShortExitsNonZero) {
    // IKM must be >= 2 * output_length; give only 16 bytes for 32-byte output.
    const auto r = run_scli(scli(),
        {"kdf", "derive", "--length", "32", "--ikm", "base64:AAAAAAAAAAAAAAAAAAAAAA=="});
    EXPECT_NE(r.exit_code, 0);
}


// ─── expand ──────────────────────────────────────────────────────────────────

TEST_F(KdfTests, ExpandProducesCorrectLength) {
    const auto r = run_scli(scli(),
        {"kdf", "expand", "--length", "32", "--prk", "base64:" + std::string(kZero48B64)});
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_EQ(r.stdout_text.size(), 44U);
}

TEST_F(KdfTests, ExpandKnownAnswer_NoInfo) {
    const auto r = run_scli(scli(),
        {"kdf", "expand", "--length", "32", "--prk", "base64:" + std::string(kZero48B64)});
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_EQ(r.stdout_text, kExpandZeroNoInfo);
}

TEST_F(KdfTests, ExpandKnownAnswer_WithInfo) {
    const auto r = run_scli(scli(),
        {"kdf", "expand", "--length", "32",
         "--prk", "base64:" + std::string(kZero48B64),
         "--info", "base64:aW5mbw=="});  // "info"
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_EQ(r.stdout_text, kExpandZeroWithInfo);
}

TEST_F(KdfTests, ExpandInfoChangesOutput) {
    const auto without = run_scli(scli(),
        {"kdf", "expand", "--length", "32", "--prk", "base64:" + std::string(kZero48B64)});
    const auto with_info = run_scli(scli(),
        {"kdf", "expand", "--length", "32",
         "--prk", "base64:" + std::string(kZero48B64),
         "--info", "base64:aW5mbw=="});
    ASSERT_EQ(without.exit_code, 0);
    ASSERT_EQ(with_info.exit_code, 0);
    EXPECT_NE(without.stdout_text, with_info.stdout_text);
}

TEST_F(KdfTests, ExpandOutputToFile) {
    const std::string out_path = tmp("kdf_expand_out.bin");
    const auto r = run_scli(scli(),
        {"kdf", "expand", "--length", "48",
         "--prk", "base64:" + std::string(kZero48B64),
         "--output", out_path});
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_EQ(std::filesystem::file_size(out_path), 48U);
}

TEST_F(KdfTests, ExpandPrkFromFile) {
    const std::string prk_path = tmp_b64("kdf_prk.bin", kZero48B64);
    const auto r = run_scli(scli(),
        {"kdf", "expand", "--length", "32", "--prk", prk_path});
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_EQ(r.stdout_text, kExpandZeroNoInfo);
}

TEST_F(KdfTests, ExpandZeroLengthExitsNonZero) {
    const auto r = run_scli(scli(),
        {"kdf", "expand", "--length", "0", "--prk", "base64:" + std::string(kZero48B64)});
    EXPECT_NE(r.exit_code, 0);
}

TEST_F(KdfTests, ExpandPrkWrongLengthExitsNonZeroWithHelpfulMessage) {
    // 64 zero bytes (not 48) — PRK must be exactly 48 bytes for HKDF-SHA384.
    const auto r = run_scli(scli(),
        {"kdf", "expand", "--length", "32", "--prk", "base64:" + std::string(kZero64B64)});
    EXPECT_NE(r.exit_code, 0);
    EXPECT_NE(r.stderr_text.find("48"), std::string::npos);
}

TEST_F(KdfTests, DeriveAboveMaxOutputLengthExitsNonZero) {
    const auto r = run_scli(scli(),
        "kdf derive --length 12241 --ikm base64:" + std::string(kZero64B64));
    EXPECT_NE(r.exit_code, 0);
}

TEST_F(KdfTests, ExpandAboveMaxOutputLengthExitsNonZero) {
    const auto r = run_scli(scli(),
        "kdf expand --length 12241 --prk base64:" + std::string(kZero48B64));
    EXPECT_NE(r.exit_code, 0);
}

}  // namespace scli_test
