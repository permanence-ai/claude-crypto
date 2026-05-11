// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <string>

#include <CLI/CLI.hpp>

#include "cli_error.hpp"
#include "cli_io.hpp"

#ifdef SAFE_CRYPTO_PQC_LIBOQS
#include "pqc_dsa.hpp"
#endif


namespace scli {

inline void register_ml_dsa(CLI::App& app)
{
    auto* sub = app.add_subcommand("ml-dsa", "ML-DSA (FIPS 204) signature scheme");
    sub->require_subcommand(1);

#ifndef SAFE_CRYPTO_PQC_LIBOQS
    for (const char* name : {"keygen", "sign", "verify"}) {
        sub->add_subcommand(name, "")->allow_extras()->callback([]() {
            die("ml-dsa is not available in this build (requires -DSAFE_CRYPTO_PQC=LIBOQS)");
        });
    }
    return;
#else

    // --- keygen ---
    auto* keygen          = sub->add_subcommand("keygen", "Generate an ML-DSA key pair");
    auto* keygen_variant  = keygen->add_option("--variant",     "Variant: 44|65|87")->required();
    auto* keygen_out_priv = keygen->add_option("--out-private", "Private key output: <file>, -, or base64 (default)");
    auto* keygen_out_pub  = keygen->add_option("--out-public",  "Public key output: <file>, -, or base64 (default)");
    keygen_variant->type_name("VARIANT");
    keygen_out_priv->type_name("SPEC");
    keygen_out_pub->type_name("SPEC");

    keygen->callback([=]() {
        const std::string variant_str = keygen_variant->as<std::string>();
        const std::string priv_spec   = keygen_out_priv->count() ? keygen_out_priv->as<std::string>() : "base64";
        const std::string pub_spec    = keygen_out_pub->count()  ? keygen_out_pub->as<std::string>()  : "base64";

        auto run = [&]<MlDsaVariant V>() {
            auto kp = ml_dsa_generate_key<V>();
            if (!kp) { die("ml-dsa keygen failed: " + kp.error().message()); }
            if (auto e = write_secret_output(priv_spec, {kp->private_key.data(), kp->private_key.size()}); !e) {
                die("failed to write private key: " + e.error());
            }
            if (auto e = write_output(pub_spec, {kp->public_key.data(), kp->public_key.size()}); !e) {
                die("failed to write public key: " + e.error());
            }
        };

        if      (variant_str == "44") { run.template operator()<MlDsaVariant::Dsa44>(); }
        else if (variant_str == "65") { run.template operator()<MlDsaVariant::Dsa65>(); }
        else if (variant_str == "87") { run.template operator()<MlDsaVariant::Dsa87>(); }
        else { die("unknown --variant '" + variant_str + "'; valid: 44 65 87"); }
    });

    // --- sign ---
    auto* sign         = sub->add_subcommand("sign", "Sign a message with an ML-DSA private key");
    auto* sign_variant = sign->add_option("--variant", "Variant: 44|65|87")->required();
    auto* sign_key     = sign->add_option("--key",     "Private key: <file>, -, or base64:DATA")->required();
    auto* sign_input   = sign->add_option("--input",   "Message: <file>, -, or base64:DATA")->required();
    auto* sign_output  = sign->add_option("--output",  "Signature output: <file>, -, or base64 (default)");
    sign_variant->type_name("VARIANT");
    sign_key->type_name("SPEC");
    sign_input->type_name("SPEC");
    sign_output->type_name("SPEC");

    sign->callback([=]() {
        const std::string variant_str = sign_variant->as<std::string>();
        const std::string key_spec    = sign_key->as<std::string>();
        const std::string in_spec     = sign_input->as<std::string>();
        const std::string out_spec    = sign_output->count() ? sign_output->as<std::string>() : "base64";

        auto key_buf = read_input_bounded(key_spec, cli_key_max_bytes);
        if (!key_buf) { die("failed to read private key: " + key_buf.error()); }
        auto msg_buf = read_input_bounded(in_spec, cli_message_max_bytes);
        if (!msg_buf) { die("failed to read message: " + msg_buf.error()); }

        auto run = [&]<MlDsaVariant V>() {
            MlDsaKeyPair<V> kp{
                .private_key = SecureBuffer(key_buf->size()),
                .public_key  = SecureBuffer(0),
            };
            std::copy(key_buf->begin(), key_buf->end(), kp.private_key.begin());

            SecureBuffer msg(msg_buf->size());
            std::copy(msg_buf->begin(), msg_buf->end(), msg.begin());

            auto sig = ml_dsa_sign<V>(kp, msg);
            if (!sig) { die("ml-dsa sign failed: " + sig.error().message()); }

            if (auto e = write_output(out_spec, {sig->data(), sig->size()}); !e) {
                die("failed to write signature: " + e.error());
            }
        };

        if      (variant_str == "44") { run.template operator()<MlDsaVariant::Dsa44>(); }
        else if (variant_str == "65") { run.template operator()<MlDsaVariant::Dsa65>(); }
        else if (variant_str == "87") { run.template operator()<MlDsaVariant::Dsa87>(); }
        else { die("unknown --variant '" + variant_str + "'; valid: 44 65 87"); }
    });

    // --- verify ---
    auto* verify           = sub->add_subcommand("verify", "Verify an ML-DSA signature (exits 0=valid, 1=invalid)");
    auto* verify_variant   = verify->add_option("--variant",   "Variant: 44|65|87")->required();
    auto* verify_key       = verify->add_option("--key",       "Public key: <file>, -, or base64:DATA")->required();
    auto* verify_input     = verify->add_option("--input",     "Message: <file>, -, or base64:DATA")->required();
    auto* verify_signature = verify->add_option("--signature", "Signature: <file>, -, or base64:DATA")->required();
    verify_variant->type_name("VARIANT");
    verify_key->type_name("SPEC");
    verify_input->type_name("SPEC");
    verify_signature->type_name("SPEC");

    verify->callback([=]() {
        const std::string variant_str = verify_variant->as<std::string>();
        const std::string key_spec    = verify_key->as<std::string>();
        const std::string in_spec     = verify_input->as<std::string>();
        const std::string sig_spec    = verify_signature->as<std::string>();

        auto key_buf = read_input_bounded(key_spec, cli_key_max_bytes);
        if (!key_buf) { die("failed to read public key: " + key_buf.error()); }
        auto msg_buf = read_input_bounded(in_spec, cli_message_max_bytes);
        if (!msg_buf) { die("failed to read message: " + msg_buf.error()); }
        auto sig_buf = read_input_bounded(sig_spec, cli_signature_max_bytes);
        if (!sig_buf) { die("failed to read signature: " + sig_buf.error()); }

        auto run = [&]<MlDsaVariant V>() {
            MlDsaPublicKey<V> pk{ .public_key = SecureBuffer(key_buf->size()) };
            std::copy(key_buf->begin(), key_buf->end(), pk.public_key.begin());

            SecureBuffer msg(msg_buf->size());
            std::copy(msg_buf->begin(), msg_buf->end(), msg.begin());

            SecureBuffer sig(sig_buf->size());
            std::copy(sig_buf->begin(), sig_buf->end(), sig.begin());

            auto result = ml_dsa_verify<V>(pk, msg, sig);
            if (!result) { std::exit(1); }
        };

        if      (variant_str == "44") { run.template operator()<MlDsaVariant::Dsa44>(); }
        else if (variant_str == "65") { run.template operator()<MlDsaVariant::Dsa65>(); }
        else if (variant_str == "87") { run.template operator()<MlDsaVariant::Dsa87>(); }
        else { die("unknown --variant '" + variant_str + "'; valid: 44 65 87"); }
    });

#endif  // SAFE_CRYPTO_PQC_LIBOQS
}

}  // namespace scli
