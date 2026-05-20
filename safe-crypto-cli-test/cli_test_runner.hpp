// SPDX-License-Identifier: Apache-2.0

#pragma once

// Utilities for invoking scli as a subprocess and capturing stdout/exit code.

#include <array>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <windows.h>
#else
#  include <poll.h>
#  include <sys/wait.h>
#  include <unistd.h>
#endif

#include "defs.hpp"


namespace scli_test {

struct RunResult {
    std::string stdout_text;
    std::string stderr_text;
    int         exit_code{};
};

// ---------------------------------------------------------------------------
// POSIX implementation — fork/pipe/poll/execv
// ---------------------------------------------------------------------------
#ifndef _WIN32

// Run scli_path with the given argv tokens and return captured stdout, stderr, and exit code.
// Stdout and stderr are drained concurrently via poll() to prevent pipe-buffer deadlocks:
// if the child fills the stderr pipe while the parent is blocked reading stdout EOF (or vice
// versa), both sides would hang without concurrent draining.
// When strip_trailing_newline is true (default), a single trailing '\n' is removed from
// stdout_text and stderr_text.  Pass false when checking raw binary output so that a last
// byte of 0x0A is not silently dropped.
[[nodiscard]]
inline auto run_scli(const std::string& scli_path, std::vector<std::string> args,
                     bool strip_trailing_newline = true) -> RunResult
{
    // Build argv: scli_path as argv[0], then each element of args, then nullptr.
    std::vector<const char*> argv_ptrs;
    argv_ptrs.reserve(args.size() + 2U);
    argv_ptrs.push_back(scli_path.c_str());
    for (const auto& a : args) { argv_ptrs.push_back(a.c_str()); }
    argv_ptrs.push_back(nullptr);

    // Create pipes for stdout and stderr.
    int stdout_pipe[2]{};
    int stderr_pipe[2]{};
    if (::pipe(stdout_pipe) != 0 || ::pipe(stderr_pipe) != 0) { return {"", "", 127}; }

    const pid_t pid = ::fork();
    if (pid < 0) {
        ::close(stdout_pipe[0]); ::close(stdout_pipe[1]);
        ::close(stderr_pipe[0]); ::close(stderr_pipe[1]);
        return {"", "", 127};
    }

    if (pid == 0) {
        // Child: redirect stdout/stderr to pipes and exec.
        ::dup2(stdout_pipe[1], STDOUT_FILENO);
        ::dup2(stderr_pipe[1], STDERR_FILENO);
        ::close(stdout_pipe[0]); ::close(stdout_pipe[1]);
        ::close(stderr_pipe[0]); ::close(stderr_pipe[1]);
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
        ::execv(scli_path.c_str(), const_cast<char* const*>(argv_ptrs.data()));
        ::_exit(127);
    }

    // Parent: close write ends; drain both read ends concurrently via poll().
    ::close(stdout_pipe[1]);
    ::close(stderr_pipe[1]);

    std::string out;
    std::string err;
    std::array<char, 4096> buf{};

    // fds[0] = stdout pipe, fds[1] = stderr pipe.
    std::array<struct pollfd, 2> fds{};
    fds[0].fd     = stdout_pipe[0];
    fds[0].events = POLLIN;
    fds[1].fd     = stderr_pipe[0];
    fds[1].events = POLLIN;

    int open_count = 2;
    while (open_count > 0) {
        const int ready = ::poll(fds.data(), static_cast<nfds_t>(fds.size()), -1);
        if (ready <= 0) { break; }

        for (auto& pfd : fds) {
            if (pfd.fd < 0) { continue; }
            if ((pfd.revents & POLLIN) != 0) {
                const ::ssize_t n = ::read(pfd.fd, buf.data(), buf.size());
                if (n > 0) {
                    (pfd.fd == stdout_pipe[0] ? out : err)
                        .append(buf.data(), static_cast<std::string::size_type>(n));
                }
            }
            if ((pfd.revents & (POLLHUP | POLLERR)) != 0) {
                // Drain any remaining bytes after HUP before closing.
                ::ssize_t n = 0;
                while ((n = ::read(pfd.fd, buf.data(), buf.size())) > 0) {
                    (pfd.fd == stdout_pipe[0] ? out : err)
                        .append(buf.data(), static_cast<std::string::size_type>(n));
                }
                ::close(pfd.fd);
                pfd.fd = -1;
                --open_count;
            }
        }
    }
    if (fds[0].fd >= 0) { ::close(fds[0].fd); }
    if (fds[1].fd >= 0) { ::close(fds[1].fd); }

    int status = 0;
    ::waitpid(pid, &status, 0);
    const int code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;  // NOLINT(hicpp-signed-bitwise)

    // Strip single trailing newline if present (suppressed for raw binary captures).
    if (strip_trailing_newline) {
        if (!out.empty() && out.back() == '\n') { out.pop_back(); }
        if (!err.empty() && err.back() == '\n') { err.pop_back(); }
    }

    return {out, err, code};
}

#else  // _WIN32

// ---------------------------------------------------------------------------
// Windows implementation — CreateProcess / CreatePipe / ReadFile
// ---------------------------------------------------------------------------

// Run scli_path with the given argv tokens and return captured stdout, stderr, and exit code.
// Stdout and stderr are piped through anonymous pipes and drained by reading both handles
// in a loop to avoid pipe-buffer deadlocks when the child writes more than one buffer of output.
// When strip_trailing_newline is true (default), a single trailing '\n' is removed from
// stdout_text and stderr_text.
[[nodiscard]]
inline auto run_scli(const std::string& scli_path, std::vector<std::string> args,
                     bool strip_trailing_newline = true) -> RunResult
{
    // Build a single command-line string: quote each argument that contains spaces.
    auto quote_arg = [](const std::string& s) -> std::string {
        if (s.find(' ') == std::string::npos && s.find('"') == std::string::npos) {
            return s;
        }
        std::string q = "\"";
        for (const char c : s) {
            if (c == '"') { q += '\\'; }
            q += c;
        }
        q += '"';
        return q;
    };

    std::string cmdline = quote_arg(scli_path);
    for (const auto& a : args) {
        cmdline += ' ';
        cmdline += quote_arg(a);
    }

    // Create pipes: stdout and stderr each get their own read/write handle pair.
    SECURITY_ATTRIBUTES sa{};
    sa.nLength              = sizeof(sa);
    sa.bInheritHandle       = TRUE;  // child inherits the write ends
    sa.lpSecurityDescriptor = nullptr;

    HANDLE stdout_rd = nullptr, stdout_wr = nullptr;
    HANDLE stderr_rd = nullptr, stderr_wr = nullptr;
    if (!CreatePipe(&stdout_rd, &stdout_wr, &sa, 0) ||
        !CreatePipe(&stderr_rd, &stderr_wr, &sa, 0)) {
        return {"", "", 127};
    }

    // Parent's read handles must NOT be inheritable.
    SetHandleInformation(stdout_rd, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(stderr_rd, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si{};
    si.cb          = sizeof(si);
    si.dwFlags     = STARTF_USESTDHANDLES;
    si.hStdOutput  = stdout_wr;
    si.hStdError   = stderr_wr;
    si.hStdInput   = GetStdHandle(STD_INPUT_HANDLE);

    PROCESS_INFORMATION pi{};
    const BOOL ok = CreateProcessA(
        nullptr,
        cmdline.data(),  // lpCommandLine must be writable
        nullptr, nullptr,
        TRUE,            // inherit handles
        0, nullptr, nullptr,
        &si, &pi);

    // Close write ends in the parent immediately after spawning.
    CloseHandle(stdout_wr);
    CloseHandle(stderr_wr);

    if (!ok) {
        CloseHandle(stdout_rd);
        CloseHandle(stderr_rd);
        return {"", "", 127};
    }
    CloseHandle(pi.hThread);

    // Drain both pipes concurrently.  We alternate between stdout and stderr
    // using PeekNamedPipe to avoid blocking on an empty pipe while the other
    // fills.  This prevents the child from deadlocking when it writes more
    // than one pipe buffer on either channel.
    std::string out;
    std::string err;
    std::array<char, 4096> buf{};

    bool stdout_open = true;
    bool stderr_open = true;

    while (stdout_open || stderr_open) {
        auto drain_pipe = [&](HANDLE h, std::string& sink, bool& pipe_open) {
            if (!pipe_open) { return; }
            DWORD avail = 0;
            if (!PeekNamedPipe(h, nullptr, 0, nullptr, &avail, nullptr)) {
                pipe_open = false;
                return;
            }
            if (avail == 0) { return; }
            DWORD nread = 0;
            const BOOL read_ok = ReadFile(h, buf.data(),
                                          static_cast<DWORD>(buf.size()),
                                          &nread, nullptr);
            if (!read_ok || nread == 0) {
                pipe_open = false;
            } else {
                sink.append(buf.data(), static_cast<std::size_t>(nread));
            }
        };

        const bool had_data_before = (out.size() + err.size()) > 0;
        drain_pipe(stdout_rd, out, stdout_open);
        drain_pipe(stderr_rd, err, stderr_open);
        const bool has_new_data = (out.size() + err.size()) > (had_data_before ? out.size() + err.size() - 1U : 0U);

        // If both pipes had nothing available, yield briefly so we don't spin.
        if (!has_new_data && (stdout_open || stderr_open)) {
            // Check whether the process has exited; if so, do a final drain.
            if (WaitForSingleObject(pi.hProcess, 0) == WAIT_OBJECT_0) {
                // Process done — drain whatever remains then exit loop.
                DWORD nread = 0;
                while (ReadFile(stdout_rd, buf.data(), static_cast<DWORD>(buf.size()), &nread, nullptr) && nread > 0) {
                    out.append(buf.data(), static_cast<std::size_t>(nread));
                }
                while (ReadFile(stderr_rd, buf.data(), static_cast<DWORD>(buf.size()), &nread, nullptr) && nread > 0) {
                    err.append(buf.data(), static_cast<std::size_t>(nread));
                }
                break;
            }
            Sleep(1);
        }
    }

    CloseHandle(stdout_rd);
    CloseHandle(stderr_rd);

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exit_code = 127;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    CloseHandle(pi.hProcess);

    if (strip_trailing_newline) {
        if (!out.empty() && out.back() == '\n') { out.pop_back(); }
        if (!err.empty() && err.back() == '\n') { err.pop_back(); }
    }

    return {out, err, static_cast<int>(exit_code)};
}

#endif  // _WIN32

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
