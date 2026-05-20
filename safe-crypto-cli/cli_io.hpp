// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cerrno>
#include <cstdint>
#include <expected>
#include <fstream>
#include <iostream>
#include <iterator>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <windows.h>
#  include <aclapi.h>
#  include <sddl.h>
#else
#  include <fcntl.h>
#  include <sys/stat.h>
#  include <unistd.h>
#endif

#include "cli_base64.hpp"

#include "secure_buffer.hpp"


namespace scli {

// Input size caps for early rejection before the crypto library validates.
// These are generous upper bounds — well above any real key, signature, or
// reasonable message size for this CLI tool.
constexpr std::size_t cli_key_max_bytes       =  64U * 1024U;             // 64 KiB
constexpr std::size_t cli_signature_max_bytes =  64U * 1024U;             // 64 KiB
constexpr std::size_t cli_message_max_bytes   =  64U * 1024U * 1024U;     // 64 MiB


// Read input specified by `spec`, rejecting inputs larger than `max_bytes`:
//   "base64:<data>"  — decode inline base64 from the command line
//   "-"              — read all of stdin as raw binary
//   <path>           — read file as raw binary
[[nodiscard]]
inline auto read_input_bounded(std::string_view spec, std::size_t max_bytes)
    -> std::expected<SecureBuffer, std::string>
{
    if (spec.starts_with("base64:")) {
        const std::string_view b64 = spec.substr(7U);
        const auto decoded = base64_decode(b64);
        if (!decoded.has_value()) {
            return std::unexpected(std::string("invalid base64 in input"));
        }
        if (decoded->size() > max_bytes) {
            return std::unexpected("input exceeds maximum allowed size of " +
                                   std::to_string(max_bytes) + " bytes");
        }
        SecureBuffer buf(decoded->size());
        std::copy(decoded->begin(), decoded->end(), buf.data());
        return buf;
    }

    std::vector<char> raw;
    raw.reserve(max_bytes + 1U);

    auto read_stream = [&](std::istream& in) -> std::expected<void, std::string> {
        char ch{};
        while (in.get(ch)) {
            raw.push_back(ch);
            if (raw.size() > max_bytes) {
                return std::unexpected("input exceeds maximum allowed size of " +
                                       std::to_string(max_bytes) + " bytes");
            }
        }
        return {};
    };

    if (spec == "-") {
        const auto r = read_stream(std::cin);
        if (!r.has_value()) { return std::unexpected(r.error()); }
    } else {
        std::ifstream file(std::string(spec), std::ios::binary);
        if (!file) {
            return std::unexpected("cannot open input file: " + std::string(spec));
        }
        const auto r = read_stream(file);
        if (!r.has_value()) { return std::unexpected(r.error()); }
    }

    SecureBuffer buf(raw.size());
    std::copy(raw.begin(), raw.end(), buf.data());
    return buf;
}


// Read input specified by `spec` (unbounded — use only where the operation
// naturally bounds the size, e.g., the library will reject oversized inputs).
//   "base64:<data>"  — decode inline base64 from the command line
//   "-"              — read all of stdin as raw binary
//   <path>           — read file as raw binary
[[nodiscard]]
inline auto read_input(std::string_view spec) -> std::expected<SecureBuffer, std::string>
{
    if (spec.starts_with("base64:")) {
        const auto decoded = base64_decode(spec.substr(7U));
        if (!decoded.has_value()) {
            return std::unexpected(std::string("invalid base64 in --input"));
        }
        SecureBuffer buf(decoded->size());
        std::copy(decoded->begin(), decoded->end(), buf.data());
        return buf;
    }

    std::vector<char> raw;
    if (spec == "-") {
        std::cin >> std::noskipws;
        raw.assign(std::istream_iterator<char>(std::cin), std::istream_iterator<char>());
    } else {
        std::ifstream file(std::string(spec), std::ios::binary);
        if (!file) {
            return std::unexpected("cannot open input file: " + std::string(spec));
        }
        file >> std::noskipws;
        raw.assign(std::istream_iterator<char>(file), std::istream_iterator<char>());
    }

    SecureBuffer buf(raw.size());
    std::copy(raw.begin(), raw.end(), buf.data());
    return buf;
}


// Write output bytes to the destination specified by `spec`:
//   ""  / "base64"   — base64-encode and print to stdout with trailing newline
//   "-"              — write raw binary to stdout
//   <path>           — write raw binary to file
[[nodiscard]]
inline auto write_output(
    std::string_view spec,
    std::span<const CryptoByte> data)
    -> std::expected<void, std::string>
{
    const bool to_base64_stdout = spec.empty() || spec == "base64";

    if (to_base64_stdout) {
        std::cout << base64_encode(data) << '\n';
        return {};
    }

    if (spec == "-") {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        std::cout.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
        return {};
    }

    std::ofstream file(std::string(spec), std::ios::binary);
    if (!file) {
        return std::unexpected("cannot open output file: " + std::string(spec));
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    file.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    if (!file) {
        return std::unexpected("write failed to: " + std::string(spec));
    }
    return {};
}


// Write secret bytes (private keys, shared secrets, IKM) to the destination
// specified by `spec`:
//   ""  / "base64"   — base64-encode and print to stdout with trailing newline
//   "-"              — write raw binary to stdout
//   <path>           — create a new file accessible only by the current user,
//                      fail if it already exists or if `spec` is a symlink
[[nodiscard]]
inline auto write_secret_output(
    std::string_view spec,
    std::span<const CryptoByte> data)
    -> std::expected<void, std::string>
{
    // stdout paths (base64 or raw) share the same behaviour as write_output.
    if (spec.empty() || spec == "base64" || spec == "-") {
        return write_output(spec, data);
    }

#ifdef _WIN32
    // Windows: CreateFileW with CREATE_NEW (exclusive, no follow-on-reparse)
    // plus an owner-only DACL equivalent to Unix mode 0600.

    // Convert UTF-8 path to wide string.
    const int wlen = MultiByteToWideChar(CP_UTF8, 0, spec.data(),
                                         static_cast<int>(spec.size()), nullptr, 0);
    if (wlen <= 0) {
        return std::unexpected("invalid path encoding: " + std::string(spec));
    }
    std::wstring wpath(static_cast<std::size_t>(wlen), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, spec.data(), static_cast<int>(spec.size()),
                        wpath.data(), wlen);

    // Reject symlinks (reparse points) before creating the file.
    const DWORD attrs = GetFileAttributesW(wpath.c_str());
    if (attrs != INVALID_FILE_ATTRIBUTES &&
        (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        return std::unexpected("secret output path is a symlink: " + std::string(spec));
    }

    // Build owner-only DACL: look up the current user's SID.
    HANDLE htoken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &htoken)) {
        return std::unexpected("cannot query process token for: " + std::string(spec));
    }

    DWORD token_info_size = 0;
    GetTokenInformation(htoken, TokenUser, nullptr, 0, &token_info_size);
    std::vector<BYTE> token_info(token_info_size);
    const BOOL got_user = GetTokenInformation(htoken, TokenUser,
                                               token_info.data(), token_info_size,
                                               &token_info_size);
    CloseHandle(htoken);
    if (!got_user) {
        return std::unexpected("cannot get token user for: " + std::string(spec));
    }

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const PSID user_sid = reinterpret_cast<TOKEN_USER*>(token_info.data())->User.Sid;

    // Grant read+write to the current user only.
    EXPLICIT_ACCESSW ea{};
    ea.grfAccessPermissions = GENERIC_READ | GENERIC_WRITE;
    ea.grfAccessMode        = SET_ACCESS;
    ea.grfInheritance       = NO_INHERITANCE;
    ea.Trustee.TrusteeForm  = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType  = TRUSTEE_IS_USER;
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    ea.Trustee.ptstrName    = reinterpret_cast<LPWSTR>(user_sid);

    PACL dacl = nullptr;
    if (SetEntriesInAclW(1, &ea, nullptr, &dacl) != ERROR_SUCCESS) {
        return std::unexpected("cannot build DACL for: " + std::string(spec));
    }

    SECURITY_DESCRIPTOR sd{};
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&sd, TRUE, dacl, FALSE);

    SECURITY_ATTRIBUTES sa{};
    sa.nLength              = sizeof(sa);
    sa.lpSecurityDescriptor = &sd;
    sa.bInheritHandle       = FALSE;

    // CREATE_NEW fails with ERROR_FILE_EXISTS if the file already exists.
    // FILE_FLAG_OPEN_REPARSE_POINT prevents following reparse points on open.
    HANDLE hfile = CreateFileW(wpath.c_str(),
                               GENERIC_WRITE,
                               0,        // no sharing
                               &sa,
                               CREATE_NEW,
                               FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                               nullptr);
    LocalFree(dacl);

    if (hfile == INVALID_HANDLE_VALUE) {
        const DWORD err = GetLastError();
        if (err == ERROR_FILE_EXISTS) {
            return std::unexpected("secret output file already exists: " + std::string(spec));
        }
        return std::unexpected("cannot create secret output file: " + std::string(spec));
    }

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const auto* ptr = reinterpret_cast<const char*>(data.data());
    std::size_t remaining = data.size();
    while (remaining > 0) {
        const DWORD to_write = static_cast<DWORD>(
            remaining > MAXDWORD ? MAXDWORD : remaining);
        DWORD written = 0;
        if (!WriteFile(hfile, ptr + (data.size() - remaining), to_write, &written, nullptr)
            || written == 0) {
            CloseHandle(hfile);
            return std::unexpected("write failed to: " + std::string(spec));
        }
        remaining -= static_cast<std::size_t>(written);
    }
    CloseHandle(hfile);
    return {};

#else
    // POSIX: open with O_CREAT|O_EXCL|O_NOFOLLOW for exclusive creation
    // without following symlinks; S_IRUSR|S_IWUSR = mode 0600.

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg,hicpp-vararg)
    const int fd = ::open(std::string(spec).c_str(),
                          O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW,  // NOLINT(hicpp-signed-bitwise)
                          S_IRUSR | S_IWUSR);  // NOLINT(hicpp-signed-bitwise)
    if (fd == -1) {
        const int err = errno;
        if (err == EEXIST) {
            return std::unexpected("secret output file already exists: " + std::string(spec));
        }
        if (err == ELOOP) {
            return std::unexpected("secret output path is a symlink: " + std::string(spec));
        }
        return std::unexpected("cannot create secret output file: " + std::string(spec));
    }

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const auto* ptr = reinterpret_cast<const char*>(data.data());
    std::size_t remaining = data.size();
    while (remaining > 0) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        const ::ssize_t written = ::write(fd, ptr + (data.size() - remaining),
                                          remaining);
        if (written <= 0) {
            ::close(fd);
            return std::unexpected("write failed to: " + std::string(spec));
        }
        remaining -= static_cast<std::size_t>(written);
    }
    ::close(fd);
    return {};
#endif
}

}  // namespace scli
