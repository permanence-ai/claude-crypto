// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <algorithm>
#include <cstdint>
#include <span>
#include <string>

#include <CLI/CLI.hpp>

#include "cli_error.hpp"
#include "cli_io.hpp"
#include "ecc.hpp"


namespace scli {

inline void register_ecdsa(CLI::App& app)
{
    auto* sub = app.add_subcommand("ecdsa", "ECDSA key generation, signing, and verification");
    sub->require_subcommand(1);

    // --- keygen ---
    auto* keygen = sub->add_subcommand("keygen", "Generate an ECDSA key pair");
    auto* keygen_curve      = keygen->add_option("--curve",       "Curve: p256|p384|p521")->required();
    auto* keygen_out_priv   = keygen->add_option("--out-private", "Private key output: <file>, - (binary stdout), or base64 (default)");
    auto* keygen_out_pub    = keygen->add_option("--out-public",  "Public key output: <file>, - (binary stdout), or base64 (default)");
    keygen_curve->type_name("CURVE");
    keygen_out_priv->type_name("SPEC");
    keygen_out_pub->type_name("SPEC");

    keygen->callback([keygen, keygen_curve, keygen_out_priv, keygen_out_pub]() {
        const std::string curve_val = keygen_curve->as<std::string>();

        EcCurve curve{};
        if      (curve_val == "p256") { curve = EcCurve::P256; }
        else if (curve_val == "p384") { curve = EcCurve::P384; }
        else if (curve_val == "p521") { curve = EcCurve::P521; }
        else { die("unknown --curve '" + curve_val + "'; valid: p256 p384 p521"); }

        const auto kp = ecdsa_generate_key(curve);
        if (!kp.has_value()) { die(kp.error()); }

        const std::string priv_spec = keygen_out_priv->count() > 0U ? keygen_out_priv->as<std::string>() : "";
        const std::string pub_spec  = keygen_out_pub->count()  > 0U ? keygen_out_pub->as<std::string>()  : "";

        const auto out_priv = write_secret_output(priv_spec, std::span<const CryptoByte>(kp->private_key_der.data(), kp->private_key_der.size()));
        if (!out_priv.has_value()) { die(out_priv.error()); }

        const auto out_pub = write_output(pub_spec, std::span<const CryptoByte>(kp->public_key_der.data(), kp->public_key_der.size()));
        if (!out_pub.has_value()) { die(out_pub.error()); }

        (void)keygen;
    });

    // --- sign ---
    auto* sign_sub = sub->add_subcommand("sign", "Sign a message with an ECDSA private key");
    auto* sign_curve  = sign_sub->add_option("--curve",  "Curve: p256|p384|p521")->required();
    auto* sign_key    = sign_sub->add_option("--key",    "Private key: <file>, - (stdin), or base64:<data>")->required();
    auto* sign_input  = sign_sub->add_option("--input",  "Message: <file>, - (stdin), or base64:<data>")->required();
    auto* sign_output = sign_sub->add_option("--output", "Signature output: <file>, - (binary stdout), or base64 (default)");
    sign_curve->type_name("CURVE");
    sign_key->type_name("SPEC");
    sign_input->type_name("SPEC");
    sign_output->type_name("SPEC");

    sign_sub->callback([sign_sub, sign_curve, sign_key, sign_input, sign_output]() {
        const std::string curve_val = sign_curve->as<std::string>();

        EcCurve curve{};
        if      (curve_val == "p256") { curve = EcCurve::P256; }
        else if (curve_val == "p384") { curve = EcCurve::P384; }
        else if (curve_val == "p521") { curve = EcCurve::P521; }
        else { die("unknown --curve '" + curve_val + "'; valid: p256 p384 p521"); }

        const auto key_buf = read_input(sign_key->as<std::string>());
        if (!key_buf.has_value()) { die(key_buf.error()); }
        const auto msg_buf = read_input(sign_input->as<std::string>());
        if (!msg_buf.has_value()) { die(msg_buf.error()); }

        EccKeyPair kp{
            .private_key_der = SecureBuffer(key_buf->size()),
            .public_key_der  = SecureBuffer(0),
        };
        std::copy(key_buf->data(), key_buf->data() + key_buf->size(), kp.private_key_der.data());

        const auto sig = ecdsa_sign(kp, curve, *msg_buf);
        if (!sig.has_value()) { die(sig.error()); }

        const std::string output_val = sign_output->count() > 0U ? sign_output->as<std::string>() : "";
        const auto out = write_output(output_val, std::span<const CryptoByte>(sig->data(), sig->size()));
        if (!out.has_value()) { die(out.error()); }

        (void)sign_sub;
    });

    // --- verify ---
    auto* verify_sub = sub->add_subcommand("verify", "Verify an ECDSA signature");
    auto* verify_curve = verify_sub->add_option("--curve",     "Curve: p256|p384|p521")->required();
    auto* verify_key   = verify_sub->add_option("--key",       "Public key: <file>, - (stdin), or base64:<data>")->required();
    auto* verify_input = verify_sub->add_option("--input",     "Message: <file>, - (stdin), or base64:<data>")->required();
    auto* verify_sig   = verify_sub->add_option("--signature", "Signature: <file>, - (stdin), or base64:<data>")->required();
    verify_curve->type_name("CURVE");
    verify_key->type_name("SPEC");
    verify_input->type_name("SPEC");
    verify_sig->type_name("SPEC");

    verify_sub->callback([verify_sub, verify_curve, verify_key, verify_input, verify_sig]() {
        const std::string curve_val = verify_curve->as<std::string>();

        EcCurve curve{};
        if      (curve_val == "p256") { curve = EcCurve::P256; }
        else if (curve_val == "p384") { curve = EcCurve::P384; }
        else if (curve_val == "p521") { curve = EcCurve::P521; }
        else { die("unknown --curve '" + curve_val + "'; valid: p256 p384 p521"); }

        const auto key_buf = read_input(verify_key->as<std::string>());
        if (!key_buf.has_value()) { die(key_buf.error()); }
        const auto msg_buf = read_input(verify_input->as<std::string>());
        if (!msg_buf.has_value()) { die(msg_buf.error()); }
        const auto sig_buf = read_input(verify_sig->as<std::string>());
        if (!sig_buf.has_value()) { die(sig_buf.error()); }

        EcPublicKey pub_key{.public_key_der = SecureBuffer(key_buf->size())};
        std::copy(key_buf->data(), key_buf->data() + key_buf->size(), pub_key.public_key_der.data());

        const auto result = ecdsa_verify(pub_key, curve, *msg_buf, *sig_buf);
        if (!result.has_value()) { die(result.error()); }
        if (!*result) {
            std::cerr << "signature invalid\n";
            std::exit(1);  // NOLINT(concurrency-mt-unsafe)
        }

        (void)verify_sub;
    });
}

}  // namespace scli
