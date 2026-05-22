// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <filesystem>
#include <fstream>
#include <string>

#ifndef _WIN32
#  include <sys/stat.h>
#endif

#include <gtest/gtest.h>

#include "cli_test_runner.hpp"


namespace scli_test {

class LogConfigTests : public ::testing::Test {
protected:
    static auto scli() -> const std::string& {
        static const std::string path{SCLI_PATH};  // NOLINT(cppcoreguidelines-pro-bounds-array-to-pointer-decay,hicpp-no-array-decay)
        return path;
    }

    static constexpr const char* VALID_INPUT = "base64:aGVsbG8=";

    static auto write_config(const std::string& json) -> std::string {
        const auto path = (std::filesystem::temp_directory_path()
                           / "scli_log_config_test.json").string();
        std::ofstream f(path);
        f << json;
        return path;
    }
};


TEST_F(LogConfigTests, StderrSinkDebugLevelEmitsTrace) {
    const auto cfg = write_config(R"({"level":"debug","sinks":[{"type":"stderr"}]})");
    const auto r = run_scli(scli(),
        {"--log-config", cfg, "digest", "--algo", "sha256", "--input", VALID_INPUT});
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_NE(r.stderr_text.find("sha"),   std::string::npos) << r.stderr_text;
    EXPECT_NE(r.stderr_text.find("input"), std::string::npos) << r.stderr_text;
}

TEST_F(LogConfigTests, StderrSinkWarnLevelSilentOnSuccess) {
    const auto cfg = write_config(R"({"level":"warn","sinks":[{"type":"stderr"}]})");
    const auto r = run_scli(scli(),
        {"--log-config", cfg, "digest", "--algo", "sha256", "--input", VALID_INPUT});
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_TRUE(r.stderr_text.empty()) << "Unexpected stderr: " << r.stderr_text;
}

TEST_F(LogConfigTests, LogConfigWinsOverLogLevel) {
    const auto cfg = write_config(R"({"level":"debug","sinks":[{"type":"stderr"}]})");
    const auto r = run_scli(scli(),
        {"--log-level", "off", "--log-config", cfg,
         "digest", "--algo", "sha256", "--input", VALID_INPUT});
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_NE(r.stderr_text.find("sha"), std::string::npos) << r.stderr_text;
}

TEST_F(LogConfigTests, NoSinksKeyDefaultsToStderr) {
    const auto cfg = write_config(R"({"level":"debug"})");
    const auto r = run_scli(scli(),
        {"--log-config", cfg, "digest", "--algo", "sha256", "--input", VALID_INPUT});
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_NE(r.stderr_text.find("sha"), std::string::npos) << r.stderr_text;
}

TEST_F(LogConfigTests, FileSinkWritesLogToFile) {
    const auto log_path = (std::filesystem::temp_directory_path()
                           / "scli_log_config_file_test.log").string();
    std::filesystem::remove(log_path);

    const auto cfg = write_config(
        R"({"level":"debug","sinks":[{"type":"file","path":")" + log_path + R"("}]})");
    const auto r = run_scli(scli(),
        {"--log-config", cfg, "digest", "--algo", "sha256", "--input", VALID_INPUT});
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_TRUE(r.stderr_text.empty()) << "Unexpected stderr: " << r.stderr_text;

    ASSERT_TRUE(std::filesystem::exists(log_path)) << "Log file not created: " << log_path;
    std::ifstream f(log_path);
    const std::string contents{std::istreambuf_iterator<char>(f),
                                std::istreambuf_iterator<char>()};
    EXPECT_NE(contents.find("sha"), std::string::npos) << "Log file contents:\n" << contents;
}

TEST_F(LogConfigTests, FileSinkMissingPathIsError) {
    const auto cfg = write_config(R"({"level":"debug","sinks":[{"type":"file"}]})");
    const auto r = run_scli(scli(),
        {"--log-config", cfg, "digest", "--algo", "sha256", "--input", VALID_INPUT});
    EXPECT_NE(r.stderr_text.find("Error"), std::string::npos)
        << "Expected error message. stderr:\n" << r.stderr_text;
}

TEST_F(LogConfigTests, MissingConfigFileFallsBackToDefaultLogging) {
    const auto r = run_scli(scli(),
        {"--log-config", "/tmp/scli_nonexistent_config_xyz.json",
         "digest", "--algo", "sha256", "--input", VALID_INPUT});
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_NE(r.stderr_text.find("Error"), std::string::npos)
        << "Expected error about missing config. stderr:\n" << r.stderr_text;
}

TEST_F(LogConfigTests, InvalidJsonFallsBackToDefaultLogging) {
    const auto cfg = write_config("{ this is not valid json }");
    const auto r = run_scli(scli(),
        {"--log-config", cfg, "digest", "--algo", "sha256", "--input", VALID_INPUT});
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_NE(r.stderr_text.find("Error"), std::string::npos)
        << "Expected JSON parse error message. stderr:\n" << r.stderr_text;
}

TEST_F(LogConfigTests, UnknownSinkTypeFallsBackToDefaultLogging) {
    const auto cfg = write_config(R"({"level":"debug","sinks":[{"type":"syslog"}]})");
    const auto r = run_scli(scli(),
        {"--log-config", cfg, "digest", "--algo", "sha256", "--input", VALID_INPUT});
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_NE(r.stderr_text.find("Error"), std::string::npos)
        << "Expected error about unknown sink. stderr:\n" << r.stderr_text;
}

#ifndef _WIN32
TEST_F(LogConfigTests, FileSinkCreatedWithOwnerOnlyPermissions) {
    const auto log_path = (std::filesystem::temp_directory_path()
                           / "scli_log_perms_test.log").string();
    std::filesystem::remove(log_path);

    const auto cfg = write_config(
        R"({"level":"debug","sinks":[{"type":"file","path":")" + log_path + R"("}]})");
    const auto r = run_scli(scli(),
        {"--log-config", cfg, "digest", "--algo", "sha256", "--input", VALID_INPUT});
    EXPECT_EQ(r.exit_code, 0);
    ASSERT_TRUE(std::filesystem::exists(log_path)) << "Log file not created";

    struct stat st{};
    ASSERT_EQ(::stat(log_path.c_str(), &st), 0);
    const auto mode = st.st_mode & 0777U;
    EXPECT_EQ(mode, 0600U)
        << "Log file has permissions " << std::oct << mode
        << ", expected 0600";
}
#endif

}  // namespace scli_test
