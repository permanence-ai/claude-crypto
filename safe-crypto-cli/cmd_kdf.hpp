// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>
#include <cstdlib>
#include <optional>
#include <span>
#include <string>

#include <CLI/CLI.hpp>

#include "cli_error.hpp"
#include "cli_io.hpp"
#include "kdf.hpp"
#include "random.hpp"


namespace scli {

inline void register_kdf(CLI::App& app)
{
    auto* sub = app.add_subcommand("kdf", "HKDF key derivation (SHA-384)");
    sub->require_subcommand(1);

    // --- derive (Extract + Expand) ---
    auto* derive = sub->add_subcommand("derive", "HKDF Extract+Expand: derive a key from IKM");
    auto* drv_length  = derive->add_option("--length",  "Output length in bytes (required)")->required();
    auto* drv_ikm     = derive->add_option("--ikm",     "Input key material: <file>, -, or base64:<data> (generated randomly if omitted)");
    auto* drv_salt    = derive->add_option("--salt",    "Optional salt: <file>, -, or base64:<data>");
    auto* drv_info    = derive->add_option("--info",    "Optional context info: <file>, -, or base64:<data>");
    auto* drv_output  = derive->add_option("--output",  "Derived key output: <file>, -, or base64 (default)");
    auto* drv_out_ikm = derive->add_option("--out-ikm", "Write generated IKM to: <file>, -, or base64 (default); only used when --ikm is omitted");
    drv_length->type_name("N");
    drv_ikm->type_name("SPEC");
    drv_salt->type_name("SPEC");
    drv_info->type_name("SPEC");
    drv_output->type_name("SPEC");
    drv_out_ikm->type_name("SPEC");

    derive->callback([derive, drv_length, drv_ikm, drv_salt, drv_info, drv_output, drv_out_ikm]() {
        const std::size_t out_len = drv_length->as<std::size_t>();
        if (out_len == 0) { die("--length must be greater than zero"); }
        if (out_len > hkdf_sha384_max_output_bytes) {
            die("--length exceeds HKDF-SHA-384 maximum (" +
                std::to_string(hkdf_sha384_max_output_bytes) + " bytes)");
        }

        // Build optional IKM.
        std::optional<SecureBuffer> ikm_opt;
        if (drv_ikm->count() > 0U) {
            auto buf = read_input_bounded(drv_ikm->as<std::string>(), cli_key_max_bytes);
            if (!buf.has_value()) { die(buf.error()); }
            ikm_opt = std::move(*buf);
        } else {
            // Generate random IKM (at least 2 * output_length per library requirement).
            auto gen = random_bytes(out_len * 2);
            if (!gen.has_value()) { die(gen.error()); }

            // Write generated IKM to --out-ikm so the caller can reproduce the derivation.
            const std::string ikm_out_spec = drv_out_ikm->count() > 0U ? drv_out_ikm->as<std::string>() : "";
            const auto ikm_out = write_secret_output(ikm_out_spec,
                std::span<const CryptoByte>(gen->data(), gen->size()));
            if (!ikm_out.has_value()) { die(ikm_out.error()); }

            ikm_opt = std::move(*gen);
        }

        // Build optional salt.
        std::optional<SecureBuffer> salt_opt;
        if (drv_salt->count() > 0U) {
            auto buf = read_input_bounded(drv_salt->as<std::string>(), cli_key_max_bytes);
            if (!buf.has_value()) { die(buf.error()); }
            salt_opt = std::move(*buf);
        }

        // Build optional info.
        std::optional<SecureBuffer> info_opt;
        if (drv_info->count() > 0U) {
            auto buf = read_input_bounded(drv_info->as<std::string>(), cli_key_max_bytes);
            if (!buf.has_value()) { die(buf.error()); }
            info_opt = std::move(*buf);
        }

        const auto result = hkdf_derive(out_len, ikm_opt, salt_opt, info_opt);
        if (!result.has_value()) { die(result.error()); }

        const std::string out_spec = drv_output->count() > 0U ? drv_output->as<std::string>() : "";
        const auto out = write_secret_output(out_spec, std::span<const CryptoByte>(result->data(), result->size()));
        if (!out.has_value()) { die(out.error()); }

        (void)derive;
    });

    // --- expand (Expand-only) ---
    auto* expand = sub->add_subcommand("expand", "HKDF Expand: expand a pseudorandom key (PRK)");
    auto* exp_length = expand->add_option("--length", "Output length in bytes (required)")->required();
    auto* exp_prk    = expand->add_option("--prk",    "Pseudorandom key: <file>, -, or base64:<data>")->required();
    auto* exp_info   = expand->add_option("--info",   "Optional context info: <file>, -, or base64:<data>");
    auto* exp_output = expand->add_option("--output", "Derived key output: <file>, -, or base64 (default)");
    exp_length->type_name("N");
    exp_prk->type_name("SPEC");
    exp_info->type_name("SPEC");
    exp_output->type_name("SPEC");

    expand->callback([expand, exp_length, exp_prk, exp_info, exp_output]() {
        const std::size_t out_len = exp_length->as<std::size_t>();
        if (out_len == 0) { die("--length must be greater than zero"); }
        if (out_len > hkdf_sha384_max_output_bytes) {
            die("--length exceeds HKDF-SHA-384 maximum (" +
                std::to_string(hkdf_sha384_max_output_bytes) + " bytes)");
        }

        auto prk_buf = read_input_bounded(exp_prk->as<std::string>(), cli_key_max_bytes);
        if (!prk_buf.has_value()) { die(prk_buf.error()); }

        // HKDF-SHA384 requires the PRK to be exactly the hash output length (48 bytes).
        constexpr std::size_t kSha384OutputBytes = 48U;
        if (prk_buf->size() != kSha384OutputBytes) {
            die("HKDF-Expand PRK must be 48 bytes for SHA-384 (got " +
                std::to_string(prk_buf->size()) + " bytes)");
        }

        std::optional<SecureBuffer> info_opt;
        if (exp_info->count() > 0U) {
            auto buf = read_input_bounded(exp_info->as<std::string>(), cli_key_max_bytes);
            if (!buf.has_value()) { die(buf.error()); }
            info_opt = std::move(*buf);
        }

        const auto result = hkdf_expand(out_len, *prk_buf, info_opt);
        if (!result.has_value()) { die(result.error()); }

        const std::string out_spec = exp_output->count() > 0U ? exp_output->as<std::string>() : "";
        const auto out = write_secret_output(out_spec, std::span<const CryptoByte>(result->data(), result->size()));
        if (!out.has_value()) { die(out.error()); }

        (void)expand;
    });
}

}  // namespace scli
