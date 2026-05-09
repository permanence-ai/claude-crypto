// SPDX-License-Identifier: Apache-2.0

#pragma once

// Utilities for invoking scli as a subprocess and capturing stdout/exit code.

#include <array>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <sys/wait.h>
#include <vector>


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

// Write raw bytes to a temp file; returns the path.
[[nodiscard]]
inline auto write_temp_file(const std::string& name, const std::vector<uint8_t>& data) -> std::string
{
    const std::string path = (std::filesystem::temp_directory_path() / name).string();
    std::ofstream f(path, std::ios::binary);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    f.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    return path;
}

// Write a base64-decoded string to a temp file; returns the path.
[[nodiscard]]
inline auto write_temp_file_b64(const std::string& name, const std::string& b64) -> std::string
{
    // Decode base64 → raw bytes.
    static constexpr const char* kAlpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::vector<uint8_t> out;
    out.reserve(b64.size() * 3 / 4);
    uint32_t acc = 0;
    int      bits = 0;
    for (const char c : b64) {
        if (c == '=') { break; }
        const char* p = std::strchr(kAlpha, c);
        if (p == nullptr) { continue; }
        acc  = (acc << 6U) | static_cast<uint32_t>(p - kAlpha);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>(acc >> static_cast<unsigned>(bits)));
        }
    }
    return write_temp_file(name, out);
}

// Read all bytes from a file.
[[nodiscard]]
inline auto read_file_bytes(const std::string& path) -> std::vector<uint8_t>
{
    std::ifstream f(path, std::ios::binary);
    f >> std::noskipws;
    return {std::istream_iterator<uint8_t>(f), std::istream_iterator<uint8_t>()};
}

}  // namespace scli_test
