// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <gtest/gtest.h>

#include "cli_test_runner.hpp"


namespace scli_test {

class DigestTests : public ::testing::Test {
protected:
    // Injected by CMake via compile definition SCLI_PATH.
    static auto scli() -> const std::string& {
        static const std::string path{SCLI_PATH};  // NOLINT(cppcoreguidelines-pro-bounds-array-to-pointer-decay,hicpp-no-array-decay)
        return path;
    }
};

// Known vectors: SHA of ASCII "hello" (base64-encoded input base64:aGVsbG8=).
TEST_F(DigestTests, Sha256OfHello) {
    const auto r = run_scli(scli(), {"digest", "--algo", "sha256", "--input", "base64:aGVsbG8="});
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_EQ(r.stdout_text, "LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=");
}

TEST_F(DigestTests, Sha384OfHello) {
    const auto r = run_scli(scli(), {"digest", "--algo", "sha384", "--input", "base64:aGVsbG8="});
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_EQ(r.stdout_text, "WeF0h3dEjGnea4ANejO7+5/xtGPkQ1TDVTvNucZm+pASWjx5+QOXvfX2oT3oKGhP");
}

TEST_F(DigestTests, Sha512OfHello) {
    const auto r = run_scli(scli(), {"digest", "--algo", "sha512", "--input", "base64:aGVsbG8="});
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_EQ(r.stdout_text, "m3HSJL1i83hdltRq0+o9czGb+8KJDKra4t/3JRlnPKcjI8PZm6XBHXx6zG4UuMXaDEZjR1wuXDre9G9zvN7AQw==");
}

TEST_F(DigestTests, Sha3_256OfHello) {
    const auto r = run_scli(scli(), {"digest", "--algo", "sha3-256", "--input", "base64:aGVsbG8="});
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_EQ(r.stdout_text, "Mzi+aU9QxfM4gUmGzfBoZFOoiLhPQk15KvS5ICOY85I=");
}

TEST_F(DigestTests, Sha3_384OfHello) {
    const auto r = run_scli(scli(), {"digest", "--algo", "sha3-384", "--input", "base64:aGVsbG8="});
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_EQ(r.stdout_text, "cgrqEQGe8GRA+/Bdh6okaAohU985B7I2MecXfOYg+hMw/wfA/d7lRpmkw+4O6diH");
}

TEST_F(DigestTests, Sha3_512OfHello) {
    const auto r = run_scli(scli(), {"digest", "--algo", "sha3-512", "--input", "base64:aGVsbG8="});
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_EQ(r.stdout_text, "ddUnw2jy7+hI7Pawc6NnZ4AIBenu8rGFfV+YTwNutt+JHXX3LZsVRRjBzViDUobR2po43ro96YtaU+XteKhJdg==");
}

TEST_F(DigestTests, UnknownAlgoExitsNonZero) {
    const auto r = run_scli(scli(), {"digest", "--algo", "md5", "--input", "base64:aGVsbG8="});
    EXPECT_NE(r.exit_code, 0);
}

TEST_F(DigestTests, EmptyInputProducesOutput) {
    // SHA-256 of empty input.
    const auto r = run_scli(scli(), {"digest", "--algo", "sha256", "--input", "base64:"});
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_FALSE(r.stdout_text.empty());
}

TEST_F(DigestTests, RejectsPaddingBeforeFinalQuantum) {
    const auto r = run_scli(scli(), {"digest", "--algo", "sha256", "--input", "base64:AA==AAAA"});
    EXPECT_NE(r.exit_code, 0);
}

TEST_F(DigestTests, RejectsPaddingInFirstTwoCharacters) {
    const auto r = run_scli(scli(), {"digest", "--algo", "sha256", "--input", "base64:A==="});
    EXPECT_NE(r.exit_code, 0);
}

}  // namespace scli_test
