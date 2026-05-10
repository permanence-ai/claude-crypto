// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <algorithm>
#include <cstdint>
#include <optional>
#include <span>
#include <string>

#include <CLI/CLI.hpp>

#include "aead.hpp"
#include "cli_error.hpp"
#include "cli_io.hpp"
#include "defs.hpp"


namespace scli {

// AEAD wire format: 12-byte IV || ciphertext (with auth tag appended by the provider).
// This is written/read verbatim when encrypt/decrypting.

inline void register_aead(CLI::App& app)
{
    auto* sub = app.add_subcommand("aead", "Authenticated encryption/decryption");

    auto* algo   = sub->add_option("--algo",   "Algorithm")->required();
    auto* op     = sub->add_option("--op",     "Operation: encrypt or decrypt")->required();
    auto* key    = sub->add_option("--key",    "Key: <file>, - (stdin), or base64:<data>")->required();
    auto* input  = sub->add_option("--input",  "Input: <file>, - (stdin), or base64:<data>")->required();
    auto* output = sub->add_option("--output", "Output: <file>, - (binary stdout), or base64 (default)");
    auto* aad    = sub->add_option("--aad",    "Additional authenticated data (optional): <file>, -, or base64:<data>");

    algo->type_name("aes256-gcm|chacha20-poly1305");
    op->type_name("encrypt|decrypt");
    key->type_name("SPEC");
    input->type_name("SPEC");
    output->type_name("SPEC");
    aad->type_name("SPEC");

    sub->callback([sub, algo, op, key, input, output, aad]() {
        const std::string algo_val   = algo->as<std::string>();
        const std::string op_val     = op->as<std::string>();
        const std::string output_val = output->count() > 0U ? output->as<std::string>() : "";

        if (op_val != "encrypt" && op_val != "decrypt") {
            die("--op must be 'encrypt' or 'decrypt'");
        }

        const auto key_buf = read_input(key->as<std::string>());
        if (!key_buf.has_value()) { die(key_buf.error()); }

        const auto in_buf = read_input(input->as<std::string>());
        if (!in_buf.has_value()) { die(in_buf.error()); }

        std::optional<SecureBuffer> aad_buf;
        if (aad->count() > 0U) {
            auto a = read_input(aad->as<std::string>());
            if (!a.has_value()) { die(a.error()); }
            aad_buf = std::move(*a);
        }

        if (algo_val == "aes256-gcm") {
            if (key_buf->size() != aes256_key_size_bytes) {
                die("--key must be exactly 32 bytes for aes256-gcm");
            }
            FixedSecureBuffer<aes256_key_size_bytes> typed_key;
            std::copy(key_buf->data(), key_buf->data() + aes256_key_size_bytes, typed_key.data());

            if (op_val == "encrypt") {
                const auto result = aes256_gcm_encrypt(typed_key, *in_buf, aad_buf);
                if (!result.has_value()) { die(result.error()); }

                // Wire format: IV || ciphertext.
                SecureBuffer wire(aes_gcm_iv_size_bytes + result->ciphertext.size());
                std::copy(result->iv.data(), result->iv.data() + aes_gcm_iv_size_bytes, wire.data());
                std::copy(result->ciphertext.data(),
                          result->ciphertext.data() + result->ciphertext.size(),
                          wire.data() + aes_gcm_iv_size_bytes);
                const auto out = write_output(output_val, std::span<const CryptoByte>(wire.data(), wire.size()));
                if (!out.has_value()) { die(out.error()); }
            } else {
                // Decrypt: parse IV || ciphertext.
                if (in_buf->size() <= aes_gcm_iv_size_bytes) {
                    die("ciphertext too short for aes256-gcm");
                }
                const std::size_t ct_size = in_buf->size() - aes_gcm_iv_size_bytes;
                AesGcmResult ct{.iv = {}, .ciphertext = SecureBuffer(ct_size)};
                std::copy(in_buf->data(), in_buf->data() + aes_gcm_iv_size_bytes, ct.iv.data());
                std::copy(in_buf->data() + aes_gcm_iv_size_bytes,
                          in_buf->data() + in_buf->size(),
                          ct.ciphertext.data());
                const auto result = aes256_gcm_decrypt(typed_key, ct, aad_buf);
                if (!result.has_value()) { die(result.error()); }
                const auto out = write_output(output_val, std::span<const CryptoByte>(result->data(), result->size()));
                if (!out.has_value()) { die(out.error()); }
            }

        } else if (algo_val == "chacha20-poly1305") {
            if (key_buf->size() != chacha20_key_size_bytes) {
                die("--key must be exactly 32 bytes for chacha20-poly1305");
            }
            FixedSecureBuffer<chacha20_key_size_bytes> typed_key;
            std::copy(key_buf->data(), key_buf->data() + chacha20_key_size_bytes, typed_key.data());

            if (op_val == "encrypt") {
                const auto result = chacha20_poly1305_encrypt(typed_key, *in_buf, aad_buf);
                if (!result.has_value()) { die(result.error()); }

                SecureBuffer wire(chacha20_poly1305_iv_size_bytes + result->ciphertext.size());
                std::copy(result->iv.data(), result->iv.data() + chacha20_poly1305_iv_size_bytes, wire.data());
                std::copy(result->ciphertext.data(),
                          result->ciphertext.data() + result->ciphertext.size(),
                          wire.data() + chacha20_poly1305_iv_size_bytes);
                const auto out = write_output(output_val, std::span<const CryptoByte>(wire.data(), wire.size()));
                if (!out.has_value()) { die(out.error()); }
            } else {
                if (in_buf->size() <= chacha20_poly1305_iv_size_bytes) {
                    die("ciphertext too short for chacha20-poly1305");
                }
                const std::size_t ct_size = in_buf->size() - chacha20_poly1305_iv_size_bytes;
                ChaCha20Poly1305Result ct{.iv = {}, .ciphertext = SecureBuffer(ct_size)};
                std::copy(in_buf->data(), in_buf->data() + chacha20_poly1305_iv_size_bytes, ct.iv.data());
                std::copy(in_buf->data() + chacha20_poly1305_iv_size_bytes,
                          in_buf->data() + in_buf->size(),
                          ct.ciphertext.data());
                const auto result = chacha20_poly1305_decrypt(typed_key, ct, aad_buf);
                if (!result.has_value()) { die(result.error()); }
                const auto out = write_output(output_val, std::span<const CryptoByte>(result->data(), result->size()));
                if (!out.has_value()) { die(out.error()); }
            }

        } else {
            die("unknown --algo '" + algo_val + "'; valid: aes256-gcm chacha20-poly1305");
        }

        (void)sub;
    });
}

}  // namespace scli
