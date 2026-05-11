// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <string>

#include <CLI/CLI.hpp>

#include "cli_error.hpp"
#include "cli_io.hpp"

#ifdef SAFE_CRYPTO_PQC_LIBOQS
#include "pqc_kem.hpp"
#endif


namespace scli {

inline void register_ml_kem(CLI::App& app)
{
    auto* sub = app.add_subcommand("ml-kem", "ML-KEM (FIPS 203) key encapsulation");
    sub->require_subcommand(1);

#ifndef SAFE_CRYPTO_PQC_LIBOQS
    // Register stub subcommands so the CLI parses them and emits a clear error.
    for (const char* name : {"keygen", "encapsulate", "decapsulate"}) {
        sub->add_subcommand(name, "")->allow_extras()->callback([]() {
            die("ml-kem is not available in this build (requires -DSAFE_CRYPTO_PQC=LIBOQS)");
        });
    }
    return;
#else

    // --- keygen ---
    auto* keygen          = sub->add_subcommand("keygen", "Generate an ML-KEM key pair");
    auto* keygen_variant  = keygen->add_option("--variant",     "Variant: 512|768|1024")->required();
    auto* keygen_out_priv = keygen->add_option("--out-private", "Private key output: <file>, -, or base64 (default)");
    auto* keygen_out_pub  = keygen->add_option("--out-public",  "Public key output: <file>, -, or base64 (default)");
    keygen_variant->type_name("VARIANT");
    keygen_out_priv->type_name("SPEC");
    keygen_out_pub->type_name("SPEC");

    keygen->callback([=]() {
        const std::string variant_str = keygen_variant->as<std::string>();
        const std::string priv_spec   = keygen_out_priv->count() ? keygen_out_priv->as<std::string>() : "base64";
        const std::string pub_spec    = keygen_out_pub->count()  ? keygen_out_pub->as<std::string>()  : "base64";

        auto run = [&]<MlKemVariant V>() {
            auto kp = ml_kem_generate_key<V>();
            if (!kp) { die("ml-kem keygen failed: " + kp.error().message()); }
            if (auto e = write_secret_output(priv_spec, {kp->private_key.data(), kp->private_key.size()}); !e) {
                die("failed to write private key: " + e.error());
            }
            if (auto e = write_output(pub_spec, {kp->public_key.data(), kp->public_key.size()}); !e) {
                die("failed to write public key: " + e.error());
            }
        };

        if      (variant_str == "512")  { run.template operator()<MlKemVariant::Kem512>();  }
        else if (variant_str == "768")  { run.template operator()<MlKemVariant::Kem768>();  }
        else if (variant_str == "1024") { run.template operator()<MlKemVariant::Kem1024>(); }
        else { die("unknown --variant '" + variant_str + "'; valid: 512 768 1024"); }
    });

    // --- encapsulate ---
    auto* encap            = sub->add_subcommand("encapsulate", "Encapsulate a shared secret under a public key");
    auto* encap_variant    = encap->add_option("--variant",        "Variant: 512|768|1024")->required();
    auto* encap_key        = encap->add_option("--key",            "Recipient public key: <file>, -, or base64:DATA")->required();
    auto* encap_out_ct     = encap->add_option("--out-ciphertext", "Ciphertext output: <file>, -, or base64 (default)");
    auto* encap_out_secret = encap->add_option("--out-secret",     "Shared secret output: <file>, -, or base64 (default)");
    encap_variant->type_name("VARIANT");
    encap_key->type_name("SPEC");
    encap_out_ct->type_name("SPEC");
    encap_out_secret->type_name("SPEC");

    encap->callback([=]() {
        const std::string variant_str  = encap_variant->as<std::string>();
        const std::string key_spec     = encap_key->as<std::string>();
        const std::string ct_spec      = encap_out_ct->count()     ? encap_out_ct->as<std::string>()     : "base64";
        const std::string secret_spec  = encap_out_secret->count() ? encap_out_secret->as<std::string>() : "base64";

        auto key_buf = read_input_bounded(key_spec, cli_key_max_bytes);
        if (!key_buf) { die("failed to read public key: " + key_buf.error()); }

        auto run = [&]<MlKemVariant V>() {
            MlKemPublicKey<V> pk{ .public_key = SecureBuffer(key_buf->size()) };
            std::copy(key_buf->begin(), key_buf->end(), pk.public_key.begin());

            auto result = ml_kem_encapsulate<V>(pk);
            if (!result) { die("ml-kem encapsulate failed: " + result.error().message()); }

            if (auto e = write_output(ct_spec, {result->ciphertext.data(), result->ciphertext.size()}); !e) {
                die("failed to write ciphertext: " + e.error());
            }
            if (auto e = write_secret_output(secret_spec, {result->shared_secret.data(), result->shared_secret.size()}); !e) {
                die("failed to write shared secret: " + e.error());
            }
        };

        if      (variant_str == "512")  { run.template operator()<MlKemVariant::Kem512>();  }
        else if (variant_str == "768")  { run.template operator()<MlKemVariant::Kem768>();  }
        else if (variant_str == "1024") { run.template operator()<MlKemVariant::Kem1024>(); }
        else { die("unknown --variant '" + variant_str + "'; valid: 512 768 1024"); }
    });

    // --- decapsulate ---
    auto* decap         = sub->add_subcommand("decapsulate", "Recover shared secret from ciphertext");
    auto* decap_variant = decap->add_option("--variant",    "Variant: 512|768|1024")->required();
    auto* decap_key     = decap->add_option("--key",        "Private key: <file>, -, or base64:DATA")->required();
    auto* decap_ct      = decap->add_option("--ciphertext", "Ciphertext: <file>, -, or base64:DATA")->required();
    auto* decap_output  = decap->add_option("--output",     "Shared secret output: <file>, -, or base64 (default)");
    decap_variant->type_name("VARIANT");
    decap_key->type_name("SPEC");
    decap_ct->type_name("SPEC");
    decap_output->type_name("SPEC");

    decap->callback([=]() {
        const std::string variant_str = decap_variant->as<std::string>();
        const std::string key_spec    = decap_key->as<std::string>();
        const std::string ct_spec     = decap_ct->as<std::string>();
        const std::string out_spec    = decap_output->count() ? decap_output->as<std::string>() : "base64";

        auto key_buf = read_input_bounded(key_spec, cli_key_max_bytes);
        if (!key_buf) { die("failed to read private key: " + key_buf.error()); }
        auto ct_buf = read_input_bounded(ct_spec, cli_key_max_bytes);
        if (!ct_buf) { die("failed to read ciphertext: " + ct_buf.error()); }

        auto run = [&]<MlKemVariant V>() {
            MlKemKeyPair<V> kp{
                .private_key = SecureBuffer(key_buf->size()),
                .public_key  = SecureBuffer(0),
            };
            std::copy(key_buf->begin(), key_buf->end(), kp.private_key.begin());

            SecureBuffer ct(ct_buf->size());
            std::copy(ct_buf->begin(), ct_buf->end(), ct.begin());

            auto ss = ml_kem_decapsulate<V>(kp, ct);
            if (!ss) { die("ml-kem decapsulate failed: " + ss.error().message()); }

            if (auto e = write_secret_output(out_spec, {ss->data(), ss->size()}); !e) {
                die("failed to write shared secret: " + e.error());
            }
        };

        if      (variant_str == "512")  { run.template operator()<MlKemVariant::Kem512>();  }
        else if (variant_str == "768")  { run.template operator()<MlKemVariant::Kem768>();  }
        else if (variant_str == "1024") { run.template operator()<MlKemVariant::Kem1024>(); }
        else { die("unknown --variant '" + variant_str + "'; valid: 512 768 1024"); }
    });

#endif  // SAFE_CRYPTO_PQC_LIBOQS
}

}  // namespace scli
