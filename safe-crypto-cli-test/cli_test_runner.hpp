// SPDX-License-Identifier: Apache-2.0

#pragma once

// Utilities for invoking scli as a subprocess and capturing stdout/exit code.

#include <array>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <sys/wait.h>


namespace scli_test {

struct RunResult {
    std::string stdout_text;
    int         exit_code{};
};

// Run `scli_path <args>` and return captured stdout + exit code.
// stdout_text has the trailing newline stripped.
[[nodiscard]]
inline auto run_scli(const std::string& scli_path, const std::string& args) -> RunResult
{
    const std::string cmd = scli_path + " " + args + " 2>/dev/null";
    // NOLINTNEXTLINE(cert-env33-c,concurrency-mt-unsafe)
    FILE* pipe = ::popen(cmd.c_str(), "r");
    if (pipe == nullptr) { return {"", 127}; }

    std::string out;
    std::array<char, 4096> buf{};
    while (::fgets(buf.data(), static_cast<int>(buf.size()), pipe) != nullptr) {
        out += buf.data();
    }
    const int status = ::pclose(pipe);
    const int code   = WIFEXITED(status) ? WEXITSTATUS(status) : -1;  // NOLINT(hicpp-signed-bitwise)

    // Strip single trailing newline if present.
    if (!out.empty() && out.back() == '\n') { out.pop_back(); }

    return {out, code};
}

}  // namespace scli_test
