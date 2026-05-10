// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "defs.hpp"


namespace scli {

[[nodiscard]]
inline auto base64_encode(std::span<const CryptoByte> data) -> std::string
{
    static constexpr std::string_view table =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::string out;
    out.reserve(((data.size() + 2U) / 3U) * 4U);

    const std::size_t full_groups = data.size() / 3U;
    for (std::size_t i = 0; i < full_groups; ++i) {
        const uint32_t b = (static_cast<uint32_t>(data[i * 3U    ]) << 16U)
                         | (static_cast<uint32_t>(data[i * 3U + 1U]) <<  8U)
                         |  static_cast<uint32_t>(data[i * 3U + 2U]);
        out += table[(b >> 18U) & 0x3FU];
        out += table[(b >> 12U) & 0x3FU];
        out += table[(b >>  6U) & 0x3FU];
        out += table[ b         & 0x3FU];
    }

    const std::size_t rem = data.size() % 3U;
    if (rem == 1U) {
        const uint32_t b = static_cast<uint32_t>(data[full_groups * 3U]) << 16U;
        out += table[(b >> 18U) & 0x3FU];
        out += table[(b >> 12U) & 0x3FU];
        out += '=';
        out += '=';
    } else if (rem == 2U) {
        const uint32_t b = (static_cast<uint32_t>(data[full_groups * 3U    ]) << 16U)
                         | (static_cast<uint32_t>(data[full_groups * 3U + 1U]) <<  8U);
        out += table[(b >> 18U) & 0x3FU];
        out += table[(b >> 12U) & 0x3FU];
        out += table[(b >>  6U) & 0x3FU];
        out += '=';
    }

    return out;
}


[[nodiscard]]
inline auto base64_decode(std::string_view input) -> std::optional<std::vector<CryptoByte>>
{
    // Build decode table: 0xFF = invalid, 0x40 = padding.
    static constexpr auto make_decode_table = []() {
        std::array<uint8_t, 256> t{};
        t.fill(0xFFU);
        for (uint8_t i = 0; i < 26U; ++i) { t['A' + i] = i;        }
        for (uint8_t i = 0; i < 26U; ++i) { t['a' + i] = 26U + i;  }
        for (uint8_t i = 0; i < 10U; ++i) { t['0' + i] = 52U + i;  }
        t['+'] = 62U;
        t['/'] = 63U;
        t['='] = 0x40U;
        return t;
    };
    static constexpr auto dtable = make_decode_table();

    // Strip trailing whitespace / newlines.
    while (!input.empty() && (input.back() == '\n' || input.back() == '\r' || input.back() == ' ')) {
        input.remove_suffix(1);
    }

    if (input.size() % 4U != 0U) { return std::nullopt; }

    std::vector<CryptoByte> out;
    out.reserve((input.size() / 4U) * 3U);

    for (std::size_t i = 0; i < input.size(); i += 4U) {
        const uint8_t c0 = dtable[static_cast<uint8_t>(input[i    ])];
        const uint8_t c1 = dtable[static_cast<uint8_t>(input[i + 1U])];
        const uint8_t c2 = dtable[static_cast<uint8_t>(input[i + 2U])];
        const uint8_t c3 = dtable[static_cast<uint8_t>(input[i + 3U])];

        if (c0 == 0xFFU || c1 == 0xFFU || c2 == 0xFFU || c3 == 0xFFU) { return std::nullopt; }

        const bool pad2 = (c2 == 0x40U);
        const bool pad3 = (c3 == 0x40U);

        if (c0 == 0x40U || c1 == 0x40U) { return std::nullopt; }
        if (pad2 && !pad3) { return std::nullopt; }  // "xx=y" is invalid
        if ((pad2 || pad3) && (i + 4U != input.size())) { return std::nullopt; }

        const uint32_t b = (static_cast<uint32_t>(c0 & 0x3FU) << 18U)
                         | (static_cast<uint32_t>(c1 & 0x3FU) << 12U)
                         | (static_cast<uint32_t>(pad2 ? 0U : (c2 & 0x3FU)) << 6U)
                         |  static_cast<uint32_t>(pad3 ? 0U : (c3 & 0x3FU));

        out.push_back(static_cast<uint8_t>((b >> 16U) & 0xFFU));
        if (!pad2) { out.push_back(static_cast<uint8_t>((b >> 8U) & 0xFFU)); }
        if (!pad3) { out.push_back(static_cast<uint8_t>( b        & 0xFFU)); }
    }

    return out;
}

}  // namespace scli
