// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>
#include <span>
#include <string>

#include <CLI/CLI.hpp>

#include "cli_error.hpp"
#include "cli_io.hpp"
#include "random.hpp"


namespace scli {

inline void register_random(CLI::App& app)
{
    auto* sub = app.add_subcommand("random", "Generate cryptographically random bytes");

    auto* length = sub->add_option("--length", "Number of bytes to generate")->required();
    auto* output = sub->add_option("--output", "Output: <file>, - (binary stdout), or base64 (default)");

    length->type_name("N");
    output->type_name("SPEC");

    sub->callback([sub, length, output]() {
        const auto n = length->as<std::size_t>();
        if (n == 0U) { die("--length must be greater than zero"); }

        const std::string output_val = output->count() > 0U ? output->as<std::string>() : "";

        const auto result = random_bytes(n);
        if (!result.has_value()) { die(result.error()); }

        const auto out = write_output(output_val, std::span<const CryptoByte>(result->data(), result->size()));
        if (!out.has_value()) { die(out.error()); }

        (void)sub;
    });
}

}  // namespace scli
