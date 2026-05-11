// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <algorithm>
#include <cstdint>
#include <span>
#include <string>

#include <CLI/CLI.hpp>

#include "cli_error.hpp"
#include "cli_io.hpp"
#include "ecdh.hpp"


namespace scli {

inline void register_ecdh(CLI::App& app)
{
    auto* sub = app.add_subcommand("ecdh", "ECDH key generation and shared-secret computation");
    sub->require_subcommand(1);

    // --- keygen ---
    auto* keygen = sub->add_subcommand("keygen", "Generate an ECDH key pair");
    auto* keygen_curve    = keygen->add_option("--curve",       "Curve: p256|p384|p521")->required();
    auto* keygen_out_priv = keygen->add_option("--out-private", "Private key output: <file>, - (binary stdout), or base64 (default)");
    auto* keygen_out_pub  = keygen->add_option("--out-public",  "Public key output: <file>, - (binary stdout), or base64 (default)");
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

        const auto kp = ecdh_generate_key(curve);
        if (!kp.has_value()) { die(kp.error()); }

        const std::string priv_spec = keygen_out_priv->count() > 0U ? keygen_out_priv->as<std::string>() : "";
        const std::string pub_spec  = keygen_out_pub->count()  > 0U ? keygen_out_pub->as<std::string>()  : "";

        const auto out_priv = write_output(priv_spec, std::span<const CryptoByte>(kp->private_key_der.data(), kp->private_key_der.size()));
        if (!out_priv.has_value()) { die(out_priv.error()); }

        const auto out_pub = write_output(pub_spec, std::span<const CryptoByte>(kp->public_key_der.data(), kp->public_key_der.size()));
        if (!out_pub.has_value()) { die(out_pub.error()); }

        (void)keygen;
    });

    // --- compute ---
    auto* compute = sub->add_subcommand("compute", "Compute ECDH shared secret");
    auto* compute_curve  = compute->add_option("--curve",       "Curve: p256|p384|p521")->required();
    auto* compute_key    = compute->add_option("--key",         "Our private key: <file>, - (stdin), or base64:<data>")->required();
    auto* compute_peer   = compute->add_option("--peer-public", "Peer public key: <file>, - (stdin), or base64:<data>")->required();
    auto* compute_output = compute->add_option("--output",      "Shared secret output: <file>, - (binary stdout), or base64 (default)");
    compute_curve->type_name("CURVE");
    compute_key->type_name("SPEC");
    compute_peer->type_name("SPEC");
    compute_output->type_name("SPEC");

    compute->callback([compute, compute_curve, compute_key, compute_peer, compute_output]() {
        const std::string curve_val = compute_curve->as<std::string>();

        EcCurve curve{};
        if      (curve_val == "p256") { curve = EcCurve::P256; }
        else if (curve_val == "p384") { curve = EcCurve::P384; }
        else if (curve_val == "p521") { curve = EcCurve::P521; }
        else { die("unknown --curve '" + curve_val + "'; valid: p256 p384 p521"); }

        const auto key_buf  = read_input(compute_key->as<std::string>());
        if (!key_buf.has_value())  { die(key_buf.error()); }
        const auto peer_buf = read_input(compute_peer->as<std::string>());
        if (!peer_buf.has_value()) { die(peer_buf.error()); }

        EccKeyPair our_kp{
            .private_key_der = SecureBuffer(key_buf->size()),
            .public_key_der  = SecureBuffer(0),
        };
        std::copy(key_buf->data(), key_buf->data() + key_buf->size(), our_kp.private_key_der.data());

        const auto secret = ecdh_compute_shared_secret(our_kp, curve, *peer_buf);
        if (!secret.has_value()) { die(secret.error()); }

        const std::string output_val = compute_output->count() > 0U ? compute_output->as<std::string>() : "";
        const auto out = write_output(output_val, std::span<const CryptoByte>(secret->data(), secret->size()));
        if (!out.has_value()) { die(out.error()); }

        (void)compute;
    });
}

}  // namespace scli
