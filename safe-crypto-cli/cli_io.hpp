// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>
#include <expected>
#include <fstream>
#include <iostream>
#include <iterator>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "cli_base64.hpp"

#include "secure_buffer.hpp"


namespace scli {

// Read input specified by `spec`:
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

}  // namespace scli
