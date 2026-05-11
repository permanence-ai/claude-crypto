// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <span>
#include <string>

#include <CLI/CLI.hpp>

#include "cli_error.hpp"
#include "cli_io.hpp"
#include "digests.hpp"
#include "sha_variant.hpp"


namespace scli {

inline void register_digest(CLI::App& app)
{
    auto* sub = app.add_subcommand("digest", "Compute a cryptographic hash");

    auto* algo   = sub->add_option("--algo", "Hash algorithm")->required();
    auto* input  = sub->add_option("--input",  "Input: <file>, - (stdin), or base64:<data>")->required();
    auto* output = sub->add_option("--output", "Output: <file>, - (binary stdout), or base64 (default)");

    algo->type_name("sha256|sha384|sha512|sha3-256|sha3-384|sha3-512");
    input->type_name("SPEC");
    output->type_name("SPEC");

    sub->callback([sub, algo, input, output]() {
        const std::string algo_val   = algo->as<std::string>();
        const std::string input_val  = input->as<std::string>();
        const std::string output_val = output->count() > 0U ? output->as<std::string>() : "";

        const auto data = read_input(input_val);
        if (!data.has_value()) { die(data.error()); }

        // Dispatch to the correct SHA variant and write output.
        const auto run_and_write = [&]<ShaVariant V>() {
            const auto result = sha<V>(*data);
            if (!result.has_value()) { die(result.error()); }
            const auto out = write_output(output_val, std::span<const CryptoByte>(result->data(), result->size()));
            if (!out.has_value()) { die(out.error()); }
        };

        if      (algo_val == "sha256")   { run_and_write.template operator()<ShaVariant::Sha256>();   }
        else if (algo_val == "sha384")   { run_and_write.template operator()<ShaVariant::Sha384>();   }
        else if (algo_val == "sha512")   { run_and_write.template operator()<ShaVariant::Sha512>();   }
        else if (algo_val == "sha3-256") { run_and_write.template operator()<ShaVariant::Sha3_256>(); }
        else if (algo_val == "sha3-384") { run_and_write.template operator()<ShaVariant::Sha3_384>(); }
        else if (algo_val == "sha3-512") { run_and_write.template operator()<ShaVariant::Sha3_512>(); }
        else {
            die("unknown --algo '" + algo_val + "'; valid: sha256 sha384 sha512 sha3-256 sha3-384 sha3-512");
        }

        (void)sub;
    });
}

}  // namespace scli
