// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <gtest/gtest.h>

#include "cli_test_runner.hpp"


namespace scli_test {

class HelpTests : public ::testing::Test {
protected:
    static auto scli() -> const std::string& {
        static const std::string path{SCLI_PATH};  // NOLINT(cppcoreguidelines-pro-bounds-array-to-pointer-decay,hicpp-no-array-decay)
        return path;
    }
};

TEST_F(HelpTests, NoArgsExitsZeroAndPrintsHelp) {
    const auto r = run_scli(scli(), {});
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_NE(r.stdout_text.find("SUBCOMMAND"), std::string::npos);
    EXPECT_NE(r.stdout_text.find("digest"), std::string::npos);
}

TEST_F(HelpTests, HelpFlagExitsZeroAndPrintsHelp) {
    const auto r = run_scli(scli(), {"--help"});
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_NE(r.stdout_text.find("SUBCOMMAND"), std::string::npos);
    EXPECT_NE(r.stdout_text.find("digest"), std::string::npos);
}

}  // namespace scli_test
