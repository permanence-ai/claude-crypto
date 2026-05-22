// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <string>

#include <gtest/gtest.h>

#include "cli_test_runner.hpp"


namespace scli_test {

class LoggingTests : public ::testing::Test {
protected:
    static auto scli() -> const std::string& {
        static const std::string path{SCLI_PATH};  // NOLINT(cppcoreguidelines-pro-bounds-array-to-pointer-decay,hicpp-no-array-decay)
        return path;
    }

    static constexpr const char* VALID_INPUT = "base64:aGVsbG8=";  // "hello"
};


// ---------------------------------------------------------------------------
// Default / warn level: no operational noise on stderr
// ---------------------------------------------------------------------------

TEST_F(LoggingTests, DefaultLevelProducesNoStderrOnSuccess) {
    const auto r = run_scli(scli(), {"digest", "--algo", "sha256", "--input", VALID_INPUT});
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_TRUE(r.stderr_text.empty()) << "Unexpected stderr: " << r.stderr_text;
}

TEST_F(LoggingTests, ExplicitWarnLevelProducesNoStderrOnSuccess) {
    const auto r = run_scli(scli(),
        {"--log-level", "warn", "digest", "--algo", "sha256", "--input", VALID_INPUT});
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_TRUE(r.stderr_text.empty()) << "Unexpected stderr: " << r.stderr_text;
}


// ---------------------------------------------------------------------------
// Debug level: entry and success trace lines appear on stderr
// ---------------------------------------------------------------------------

TEST_F(LoggingTests, DebugLevelEmitsEntryAndSuccessLines) {
    const auto r = run_scli(scli(),
        {"--log-level", "debug", "digest", "--algo", "sha256", "--input", VALID_INPUT});
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_NE(r.stderr_text.find("sha"),   std::string::npos) << r.stderr_text;
    EXPECT_NE(r.stderr_text.find("input"), std::string::npos) << r.stderr_text;
    EXPECT_NE(r.stderr_text.find("digest"), std::string::npos) << r.stderr_text;
}

TEST_F(LoggingTests, DebugLevelEqualsFormAccepted) {
    const auto r = run_scli(scli(),
        {"--log-level=debug", "digest", "--algo", "sha256", "--input", VALID_INPUT});
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_NE(r.stderr_text.find("sha"), std::string::npos) << r.stderr_text;
}


// ---------------------------------------------------------------------------
// SCLI_LOG_LEVEL env var
// ---------------------------------------------------------------------------

TEST_F(LoggingTests, EnvVarDebugEmitsTrace) {
    const auto old = ::getenv("SCLI_LOG_LEVEL");  // NOLINT(concurrency-mt-unsafe)
    ::setenv("SCLI_LOG_LEVEL", "debug", 1);        // NOLINT(concurrency-mt-unsafe)

    const auto r = run_scli(scli(), {"digest", "--algo", "sha256", "--input", VALID_INPUT});

    if (old) { ::setenv("SCLI_LOG_LEVEL", old, 1); }   // NOLINT(concurrency-mt-unsafe)
    else      { ::unsetenv("SCLI_LOG_LEVEL"); }          // NOLINT(concurrency-mt-unsafe)

    EXPECT_EQ(r.exit_code, 0);
    EXPECT_NE(r.stderr_text.find("sha"), std::string::npos) << r.stderr_text;
}

TEST_F(LoggingTests, EnvVarOffSilencesOperationalOutput) {
    const auto old = ::getenv("SCLI_LOG_LEVEL");  // NOLINT(concurrency-mt-unsafe)
    ::setenv("SCLI_LOG_LEVEL", "off", 1);          // NOLINT(concurrency-mt-unsafe)

    const auto r = run_scli(scli(), {"digest", "--algo", "sha256", "--input", VALID_INPUT});

    if (old) { ::setenv("SCLI_LOG_LEVEL", old, 1); }  // NOLINT(concurrency-mt-unsafe)
    else      { ::unsetenv("SCLI_LOG_LEVEL"); }         // NOLINT(concurrency-mt-unsafe)

    EXPECT_EQ(r.exit_code, 0);
    EXPECT_TRUE(r.stderr_text.empty()) << "Unexpected stderr: " << r.stderr_text;
}


// ---------------------------------------------------------------------------
// --log-level off: fatal errors still visible
// ---------------------------------------------------------------------------

TEST_F(LoggingTests, OffLevelStillEmitsFatalError) {
    const auto r = run_scli(scli(),
        {"--log-level", "off", "digest", "--algo", "nope", "--input", VALID_INPUT});
    EXPECT_NE(r.exit_code, 0);
    EXPECT_NE(r.stderr_text.find("Error"), std::string::npos)
        << "Fatal error was silenced at --log-level off. stderr: " << r.stderr_text;
}

TEST_F(LoggingTests, WarnLevelEmitsFatalErrorOnce) {
    const auto r = run_scli(scli(),
        {"--log-level", "warn", "digest", "--algo", "nope", "--input", VALID_INPUT});
    EXPECT_NE(r.exit_code, 0);

    std::size_t count = 0;
    std::size_t pos   = 0;
    while ((pos = r.stderr_text.find("nope", pos)) != std::string::npos) {
        ++count;
        ++pos;
    }
    EXPECT_EQ(count, 1U) << "Error message duplicated. stderr:\n" << r.stderr_text;
}


// ---------------------------------------------------------------------------
// Unknown log level: falls back to warn (silent on success)
// ---------------------------------------------------------------------------

TEST_F(LoggingTests, UnknownLevelFallsBackToWarn) {
    const auto r = run_scli(scli(),
        {"--log-level", "verbose", "digest", "--algo", "sha256", "--input", VALID_INPUT});
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_TRUE(r.stderr_text.empty()) << "Unexpected stderr: " << r.stderr_text;
}

}  // namespace scli_test
