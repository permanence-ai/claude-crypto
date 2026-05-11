// SPDX-License-Identifier: Apache-2.0

#pragma once

// Utilities for invoking scli as a subprocess and capturing stdout/exit code.
//
// run_scli() uses fork/execv (no shell) so argument values are passed verbatim
// and there is no shared stderr temp file to race on under parallel ctest runs.

#include <array>
#include <cstring>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include <poll.h>
#include <sys/wait.h>
#include <unistd.h>

#include "defs.hpp"


namespace scli_test {

struct RunResult {
    std::string stdout_text;
    std::string stderr_text;
    int         exit_code{};
};

// Split a whitespace-delimited argument string into tokens.
// Handles multiple consecutive spaces; does not handle quoting (test args
// should not contain spaces — use file paths that are space-free).
[[nodiscard]]
inline auto split_args(const std::string& s) -> std::vector<std::string>
{
    std::vector<std::string> tokens;
    std::size_t i = 0;
    while (i < s.size()) {
        while (i < s.size() && s[i] == ' ') { ++i; }
        if (i >= s.size()) { break; }
        std::size_t j = i;
        while (j < s.size() && s[j] != ' ') { ++j; }
        tokens.push_back(s.substr(i, j - i));
        i = j;
    }
    return tokens;
}

// Drain a non-blocking read end of a pipe into `out` until EOF.
inline void drain_pipe(int fd, std::string& out)
{
    std::array<char, 4096> buf{};
    ::ssize_t n = 0;
    while ((n = ::read(fd, buf.data(), buf.size())) > 0) {
        out.append(buf.data(), static_cast<std::size_t>(n));
    }
}

// Run `scli_path <args>` via fork/execv and return captured stdout, stderr,
// and exit code.  Trailing newlines on stdout_text and stderr_text are stripped.
// `args` is a whitespace-delimited string split into argv tokens — values must
// not contain spaces (use file paths under /tmp which are space-free).
[[nodiscard]]
inline auto run_scli(const std::string& scli_path, const std::string& args) -> RunResult
{
    // Build argv: scli_path + tokens from args.
    const auto tokens = split_args(args);
    std::vector<const char*> argv;
    argv.reserve(tokens.size() + 2U);
    argv.push_back(scli_path.c_str());
    for (const auto& t : tokens) { argv.push_back(t.c_str()); }
    argv.push_back(nullptr);

    // Create pipes for stdout and stderr.
    std::array<int, 2> stdout_pipe{};
    std::array<int, 2> stderr_pipe{};
    if (::pipe(stdout_pipe.data()) != 0 || ::pipe(stderr_pipe.data()) != 0) {
        return {"", "pipe() failed", 127};
    }

    const pid_t pid = ::fork();
    if (pid == -1) {
        ::close(stdout_pipe[0]); ::close(stdout_pipe[1]);
        ::close(stderr_pipe[0]); ::close(stderr_pipe[1]);
        return {"", "fork() failed", 127};
    }

    if (pid == 0) {
        // Child: wire up pipes and exec.
        ::close(stdout_pipe[0]);
        ::close(stderr_pipe[0]);
        ::dup2(stdout_pipe[1], STDOUT_FILENO);  // NOLINT(hicpp-signed-bitwise)
        ::dup2(stderr_pipe[1], STDERR_FILENO);  // NOLINT(hicpp-signed-bitwise)
        ::close(stdout_pipe[1]);
        ::close(stderr_pipe[1]);
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
        ::execv(scli_path.c_str(), const_cast<char* const*>(argv.data()));
        ::_exit(127);  // execv failed
    }

    // Parent: close write ends, drain both pipes, then wait.
    ::close(stdout_pipe[1]);
    ::close(stderr_pipe[1]);

    std::string out;
    std::string err;

    // Poll both pipes until both reach EOF.
    std::array<struct ::pollfd, 2> fds{};
    fds[0] = {stdout_pipe[0], POLLIN, 0};
    fds[1] = {stderr_pipe[0], POLLIN, 0};
    int open_count = 2;

    while (open_count > 0) {
        const int ready = ::poll(fds.data(), static_cast<::nfds_t>(fds.size()), -1);
        if (ready <= 0) { break; }
        for (auto& pfd : fds) {
            if (pfd.fd < 0) { continue; }
            if ((pfd.revents & POLLIN) != 0) {  // NOLINT(hicpp-signed-bitwise)
                std::array<char, 4096> buf{};
                const ::ssize_t n = ::read(pfd.fd, buf.data(), buf.size());
                if (n > 0) {
                    if (pfd.fd == stdout_pipe[0]) { out.append(buf.data(), static_cast<std::size_t>(n)); }
                    else                          { err.append(buf.data(), static_cast<std::size_t>(n)); }
                }
            }
            if ((pfd.revents & (POLLHUP | POLLERR)) != 0) {  // NOLINT(hicpp-signed-bitwise)
                // Drain any remaining bytes after HUP.
                if (pfd.fd == stdout_pipe[0]) { drain_pipe(pfd.fd, out); }
                else                          { drain_pipe(pfd.fd, err); }
                ::close(pfd.fd);
                pfd.fd = -1;
                --open_count;
            }
        }
    }
    ::close(stdout_pipe[0]);
    ::close(stderr_pipe[0]);

    int status = 0;
    ::waitpid(pid, &status, 0);
    const int code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;  // NOLINT(hicpp-signed-bitwise)

    // Strip single trailing newline if present.
    if (!out.empty() && out.back() == '\n') { out.pop_back(); }
    if (!err.empty() && err.back() == '\n') { err.pop_back(); }

    return {out, err, code};
}

// Write raw bytes to a temp file; returns the path.
[[nodiscard]]
inline auto write_temp_file(const std::string& name, const std::vector<CryptoByte>& data) -> std::string
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
    std::vector<CryptoByte> out;
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
inline auto read_file_bytes(const std::string& path) -> std::vector<CryptoByte>
{
    std::ifstream f(path, std::ios::binary);
    f >> std::noskipws;
    return {std::istream_iterator<CryptoByte>(f), std::istream_iterator<CryptoByte>()};
}

}  // namespace scli_test
