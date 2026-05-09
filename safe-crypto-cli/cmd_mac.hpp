// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <algorithm>
#include <cstdint>
#include <span>
#include <string>

#include <CLI/CLI.hpp>

#include "cli_error.hpp"
#include "cli_io.hpp"
#include "mac.hpp"
#include "sha_variant.hpp"


namespace scli {

inline void register_mac(CLI::App& app)
{
    auto* sub = app.add_subcommand("mac", "Generate or verify an HMAC");

    auto* algo   = sub->add_option("--algo",   "Hash algorithm")->required();
    auto* key    = sub->add_option("--key",    "Key: <file>, - (stdin), or base64:<data>")->required();
    auto* input  = sub->add_option("--input",  "Message: <file>, - (stdin), or base64:<data>")->required();
    auto* output = sub->add_option("--output", "Output: <file>, - (binary stdout), or base64 (default)");
    auto* verify = sub->add_option("--verify", "Verify against MAC: <file>, - (stdin), or base64:<data>");

    algo->type_name("sha256|sha384|sha512");
    key->type_name("SPEC");
    input->type_name("SPEC");
    output->type_name("SPEC");
    verify->type_name("SPEC");

    sub->callback([sub, algo, key, input, output, verify]() {
        const std::string algo_val  = algo->as<std::string>();
        const std::string key_val   = key->as<std::string>();
        const std::string input_val = input->as<std::string>();

        const auto key_buf = read_input(key_val);
        if (!key_buf.has_value()) { die(key_buf.error()); }
        const auto msg_buf = read_input(input_val);
        if (!msg_buf.has_value()) { die(msg_buf.error()); }

        const bool verify_mode = (verify->count() > 0U);

        const auto run = [&]<ShaVariant V>() {
            if (verify_mode) {
                const auto mac_buf = read_input(verify->as<std::string>());
                if (!mac_buf.has_value()) { die(mac_buf.error()); }

                if (mac_buf->size() != sha_output_size(V)) {
                    die("--verify MAC length mismatch for " + algo_val);
                }

                // Copy into FixedSecureBuffer for hmac_verify.
                FixedSecureBuffer<sha_output_size(V)> expected_mac;
                std::copy(mac_buf->data(), mac_buf->data() + mac_buf->size(), expected_mac.data());

                const auto result = hmac_verify<V>(*key_buf, *msg_buf, expected_mac);
                if (!result.has_value()) { die(result.error()); }
                if (!*result) {
                    std::cerr << "MAC mismatch\n";
                    std::exit(1);  // NOLINT(concurrency-mt-unsafe)
                }
                // Exit 0 = match (no output).
            } else {
                const std::string output_val = output->count() > 0U ? output->as<std::string>() : "";
                const auto result = hmac_generate<V>(*key_buf, *msg_buf);
                if (!result.has_value()) { die(result.error()); }
                const auto out = write_output(output_val, std::span<const uint8_t>(result->data(), result->size()));
                if (!out.has_value()) { die(out.error()); }
            }
        };

        if      (algo_val == "sha256") { run.template operator()<ShaVariant::Sha256>(); }
        else if (algo_val == "sha384") { run.template operator()<ShaVariant::Sha384>(); }
        else if (algo_val == "sha512") { run.template operator()<ShaVariant::Sha512>(); }
        else {
            die("unknown --algo '" + algo_val + "'; valid: sha256 sha384 sha512");
        }

        (void)sub;
    });
}

}  // namespace scli
