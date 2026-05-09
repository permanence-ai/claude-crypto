// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <gtest/gtest.h>

#include "cli_test_runner.hpp"


namespace scli_test {

class MacTests : public ::testing::Test {
protected:
    static auto scli() -> const std::string& {
        static const std::string path{SCLI_PATH};  // NOLINT(cppcoreguidelines-pro-bounds-array-to-pointer-decay,hicpp-no-array-decay)
        return path;
    }

    // A fixed 32-byte key (base64) for deterministic tests.
    static constexpr const char* kKey = "base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
};

TEST_F(MacTests, GenerateProducesNonEmptyOutput) {
    const auto r = run_scli(scli(),
        std::string("mac --algo sha256 --key ") + kKey + " --input base64:aGVsbG8=");
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_FALSE(r.stdout_text.empty());
}

TEST_F(MacTests, VerifySucceedsWithCorrectMac) {
    // Compute MAC, then verify it.
    const auto gen = run_scli(scli(),
        std::string("mac --algo sha256 --key ") + kKey + " --input base64:aGVsbG8=");
    ASSERT_EQ(gen.exit_code, 0);

    const auto verify = run_scli(scli(),
        std::string("mac --algo sha256 --key ") + kKey +
        " --input base64:aGVsbG8= --verify base64:" + gen.stdout_text);
    EXPECT_EQ(verify.exit_code, 0);
    EXPECT_TRUE(verify.stdout_text.empty());  // verify mode produces no output
}

TEST_F(MacTests, VerifyFailsWithWrongMessage) {
    const auto gen = run_scli(scli(),
        std::string("mac --algo sha256 --key ") + kKey + " --input base64:aGVsbG8=");
    ASSERT_EQ(gen.exit_code, 0);

    // Different message: "world" instead of "hello".
    const auto verify = run_scli(scli(),
        std::string("mac --algo sha256 --key ") + kKey +
        " --input base64:d29ybGQ= --verify base64:" + gen.stdout_text);
    EXPECT_NE(verify.exit_code, 0);
}

TEST_F(MacTests, VerifyFailsWithWrongKey) {
    const auto gen = run_scli(scli(),
        std::string("mac --algo sha256 --key ") + kKey + " --input base64:aGVsbG8=");
    ASSERT_EQ(gen.exit_code, 0);

    const std::string other_key = "base64:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
    const auto verify = run_scli(scli(),
        std::string("mac --algo sha256 --key ") + other_key +
        " --input base64:aGVsbG8= --verify base64:" + gen.stdout_text);
    EXPECT_NE(verify.exit_code, 0);
}

TEST_F(MacTests, Sha384Variant) {
    const auto r = run_scli(scli(),
        std::string("mac --algo sha384 --key ") + kKey + " --input base64:aGVsbG8=");
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_FALSE(r.stdout_text.empty());
}

TEST_F(MacTests, Sha512Variant) {
    const auto r = run_scli(scli(),
        std::string("mac --algo sha512 --key ") + kKey + " --input base64:aGVsbG8=");
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_FALSE(r.stdout_text.empty());
}

TEST_F(MacTests, UnknownAlgoExitsNonZero) {
    const auto r = run_scli(scli(),
        std::string("mac --algo sha1 --key ") + kKey + " --input base64:aGVsbG8=");
    EXPECT_NE(r.exit_code, 0);
}

}  // namespace scli_test
