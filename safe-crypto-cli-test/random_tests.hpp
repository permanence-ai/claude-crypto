// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <string>

#include <gtest/gtest.h>

#include "cli_test_runner.hpp"


namespace scli_test {

class RandomTests : public ::testing::Test {
protected:
    static auto scli() -> const std::string& {
        static const std::string path{SCLI_PATH};  // NOLINT(cppcoreguidelines-pro-bounds-array-to-pointer-decay,hicpp-no-array-decay)
        return path;
    }
};

TEST_F(RandomTests, Produces32BytesAs44CharBase64) {
    const auto r = run_scli(scli(), "random --length 32");
    EXPECT_EQ(r.exit_code, 0);
    // 32 bytes → 44 base64 chars (including padding '=').
    EXPECT_EQ(r.stdout_text.size(), 44U);
}

TEST_F(RandomTests, Produces64BytesAs88CharBase64) {
    const auto r = run_scli(scli(), "random --length 64");
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_EQ(r.stdout_text.size(), 88U);
}

TEST_F(RandomTests, Produces1ByteAs4CharBase64) {
    const auto r = run_scli(scli(), "random --length 1");
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_EQ(r.stdout_text.size(), 4U);
}

TEST_F(RandomTests, TwoCalls_ProduceDifferentOutput) {
    const auto r1 = run_scli(scli(), "random --length 32");
    const auto r2 = run_scli(scli(), "random --length 32");
    ASSERT_EQ(r1.exit_code, 0);
    ASSERT_EQ(r2.exit_code, 0);
    // Probability of collision is negligible (1/2^256).
    EXPECT_NE(r1.stdout_text, r2.stdout_text);
}

TEST_F(RandomTests, ZeroLengthExitsNonZero) {
    const auto r = run_scli(scli(), "random --length 0");
    EXPECT_NE(r.exit_code, 0);
}

}  // namespace scli_test
