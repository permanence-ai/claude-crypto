// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>

#include <CLI/CLI.hpp>

#include "asymmetric.hpp"
#include "cli_error.hpp"
#include "cli_io.hpp"
#include "kdf.hpp"


namespace scli {

// Parse --bits value to RsaKeyBits; dies on unknown value.
[[nodiscard]]
inline auto parse_rsa_bits(const std::string& bits_str) -> RsaKeyBits
{
    if (bits_str == "3072") { return RsaKeyBits::Bits3072; }
    if (bits_str == "4096") { return RsaKeyBits::Bits4096; }
    die("unknown --bits '" + bits_str + "'; valid: 3072 4096");
}

// Build an optional<SecureBuffer> from a CLI option (empty → nullopt).
[[nodiscard]]
inline auto read_optional_input(CLI::Option* opt) -> std::optional<SecureBuffer>
{
    if (opt->count() == 0U) { return std::nullopt; }
    auto buf = read_input(opt->as<std::string>());
    if (!buf.has_value()) { die(buf.error()); }
    return std::move(*buf);
}


inline void register_rsa(CLI::App& app)
{
    auto* sub = app.add_subcommand("rsa",
        "RSA key generation, OAEP encryption/decryption, and PSS signing/verification");
    sub->require_subcommand(1);

    // --- keygen ---
    auto* keygen = sub->add_subcommand("keygen", "Generate an RSA key pair");
    auto* kg_bits     = keygen->add_option("--bits",        "Key size: 3072|4096")->required();
    auto* kg_out_priv = keygen->add_option("--out-private", "Private key output (PKCS#1 DER): <file>, -, or base64 (default)");
    auto* kg_out_pub  = keygen->add_option("--out-public",  "Public key output (SPKI DER): <file>, -, or base64 (default)");
    kg_bits->type_name("BITS");
    kg_out_priv->type_name("SPEC");
    kg_out_pub->type_name("SPEC");

    keygen->callback([keygen, kg_bits, kg_out_priv, kg_out_pub]() {
        const std::string bits_str   = kg_bits->as<std::string>();
        const std::string priv_spec  = kg_out_priv->count() > 0U ? kg_out_priv->as<std::string>() : "";
        const std::string pub_spec   = kg_out_pub->count()  > 0U ? kg_out_pub->as<std::string>()  : "";

        const auto run = [&]<RsaKeyBits KB>() {
            const auto kp = generate_rsa_key<KB>();
            if (!kp.has_value()) { die(kp.error()); }
            const auto op = write_secret_output(priv_spec, std::span<const CryptoByte>(kp->private_key_der.data(), kp->private_key_der.size()));
            if (!op.has_value()) { die(op.error()); }
            const auto oq = write_output(pub_spec, std::span<const CryptoByte>(kp->public_key_der.data(), kp->public_key_der.size()));
            if (!oq.has_value()) { die(oq.error()); }
        };

        const RsaKeyBits kb = parse_rsa_bits(bits_str);
        if (kb == RsaKeyBits::Bits3072) { run.template operator()<RsaKeyBits::Bits3072>(); }
        else                            { run.template operator()<RsaKeyBits::Bits4096>(); }

        (void)keygen;
    });

    // --- oaep-encrypt ---
    auto* enc = sub->add_subcommand("oaep-encrypt", "RSA-OAEP encrypt a message");
    auto* enc_bits   = enc->add_option("--bits",   "Key size: 3072|4096")->required();
    auto* enc_key    = enc->add_option("--key",    "Public key DER: <file>, -, or base64:<data>")->required();
    auto* enc_input  = enc->add_option("--input",  "Plaintext: <file>, -, or base64:<data>")->required();
    auto* enc_output = enc->add_option("--output", "Ciphertext output: <file>, -, or base64 (default)");
    auto* enc_label  = enc->add_option("--label",  "Optional OAEP label: <file>, -, or base64:<data>");
    enc_bits->type_name("BITS");
    enc_key->type_name("SPEC");
    enc_input->type_name("SPEC");
    enc_output->type_name("SPEC");
    enc_label->type_name("SPEC");

    enc->callback([enc, enc_bits, enc_key, enc_input, enc_output, enc_label]() {
        auto pub_buf = read_input(enc_key->as<std::string>());
        if (!pub_buf.has_value()) { die(pub_buf.error()); }
        auto pt_buf = read_input(enc_input->as<std::string>());
        if (!pt_buf.has_value()) { die(pt_buf.error()); }
        auto label_opt = read_optional_input(enc_label);
        const std::string out_spec = enc_output->count() > 0U ? enc_output->as<std::string>() : "";

        const auto run = [&]<RsaKeyBits KB>() {
            RsaPublicKey<KB> pub{.public_key_der = SecureBuffer(pub_buf->size())};
            std::copy(pub_buf->data(), pub_buf->data() + pub_buf->size(), pub.public_key_der.data());

            const auto ct = rsa_oaep_encrypt<KB>(pub, *pt_buf, label_opt);
            if (!ct.has_value()) { die(ct.error()); }

            const auto out = write_output(out_spec, std::span<const CryptoByte>(ct->data(), ct->size()));
            if (!out.has_value()) { die(out.error()); }
        };

        const RsaKeyBits kb = parse_rsa_bits(enc_bits->as<std::string>());
        if (kb == RsaKeyBits::Bits3072) { run.template operator()<RsaKeyBits::Bits3072>(); }
        else                            { run.template operator()<RsaKeyBits::Bits4096>(); }

        (void)enc;
    });

    // --- oaep-decrypt ---
    auto* dec = sub->add_subcommand("oaep-decrypt", "RSA-OAEP decrypt a ciphertext");
    auto* dec_bits   = dec->add_option("--bits",   "Key size: 3072|4096")->required();
    auto* dec_key    = dec->add_option("--key",    "Private key DER: <file>, -, or base64:<data>")->required();
    auto* dec_input  = dec->add_option("--input",  "Ciphertext: <file>, -, or base64:<data>")->required();
    auto* dec_output = dec->add_option("--output", "Plaintext output: <file>, -, or base64 (default)");
    auto* dec_label  = dec->add_option("--label",  "Optional OAEP label: <file>, -, or base64:<data>");
    dec_bits->type_name("BITS");
    dec_key->type_name("SPEC");
    dec_input->type_name("SPEC");
    dec_output->type_name("SPEC");
    dec_label->type_name("SPEC");

    dec->callback([dec, dec_bits, dec_key, dec_input, dec_output, dec_label]() {
        auto priv_buf = read_input(dec_key->as<std::string>());
        if (!priv_buf.has_value()) { die(priv_buf.error()); }
        auto ct_buf = read_input(dec_input->as<std::string>());
        if (!ct_buf.has_value()) { die(ct_buf.error()); }
        auto label_opt = read_optional_input(dec_label);
        const std::string out_spec = dec_output->count() > 0U ? dec_output->as<std::string>() : "";

        const auto run = [&]<RsaKeyBits KB>() {
            RsaKeyPair<KB> kp{
                .private_key_der = SecureBuffer(priv_buf->size()),
                .public_key_der  = SecureBuffer(0),
            };
            std::copy(priv_buf->data(), priv_buf->data() + priv_buf->size(), kp.private_key_der.data());

            const auto pt = rsa_oaep_decrypt<KB>(kp, *ct_buf, label_opt);
            if (!pt.has_value()) { die(pt.error()); }

            const auto out = write_output(out_spec, std::span<const CryptoByte>(pt->data(), pt->size()));
            if (!out.has_value()) { die(out.error()); }
        };

        const RsaKeyBits kb = parse_rsa_bits(dec_bits->as<std::string>());
        if (kb == RsaKeyBits::Bits3072) { run.template operator()<RsaKeyBits::Bits3072>(); }
        else                            { run.template operator()<RsaKeyBits::Bits4096>(); }

        (void)dec;
    });

    // --- pss-sign ---
    auto* sign = sub->add_subcommand("pss-sign", "RSA-PSS sign a message");
    auto* sign_bits   = sign->add_option("--bits",   "Key size: 3072|4096")->required();
    auto* sign_key    = sign->add_option("--key",    "Private key DER: <file>, -, or base64:<data>")->required();
    auto* sign_input  = sign->add_option("--input",  "Message: <file>, -, or base64:<data>")->required();
    auto* sign_output = sign->add_option("--output", "Signature output: <file>, -, or base64 (default)");
    sign_bits->type_name("BITS");
    sign_key->type_name("SPEC");
    sign_input->type_name("SPEC");
    sign_output->type_name("SPEC");

    sign->callback([sign, sign_bits, sign_key, sign_input, sign_output]() {
        auto priv_buf = read_input(sign_key->as<std::string>());
        if (!priv_buf.has_value()) { die(priv_buf.error()); }
        auto msg_buf = read_input(sign_input->as<std::string>());
        if (!msg_buf.has_value()) { die(msg_buf.error()); }
        const std::string out_spec = sign_output->count() > 0U ? sign_output->as<std::string>() : "";

        const auto run = [&]<RsaKeyBits KB>() {
            RsaKeyPair<KB> kp{
                .private_key_der = SecureBuffer(priv_buf->size()),
                .public_key_der  = SecureBuffer(0),
            };
            std::copy(priv_buf->data(), priv_buf->data() + priv_buf->size(), kp.private_key_der.data());

            const auto sig = rsa_pss_sign<KB>(kp, *msg_buf);
            if (!sig.has_value()) { die(sig.error()); }

            const auto out = write_output(out_spec, std::span<const CryptoByte>(sig->data(), sig->size()));
            if (!out.has_value()) { die(out.error()); }
        };

        const RsaKeyBits kb = parse_rsa_bits(sign_bits->as<std::string>());
        if (kb == RsaKeyBits::Bits3072) { run.template operator()<RsaKeyBits::Bits3072>(); }
        else                            { run.template operator()<RsaKeyBits::Bits4096>(); }

        (void)sign;
    });

    // --- pss-verify ---
    auto* verify = sub->add_subcommand("pss-verify", "RSA-PSS verify a signature");
    auto* verify_bits  = verify->add_option("--bits",      "Key size: 3072|4096")->required();
    auto* verify_key   = verify->add_option("--key",       "Public key DER: <file>, -, or base64:<data>")->required();
    auto* verify_input = verify->add_option("--input",     "Message: <file>, -, or base64:<data>")->required();
    auto* verify_sig   = verify->add_option("--signature", "Signature: <file>, -, or base64:<data>")->required();
    verify_bits->type_name("BITS");
    verify_key->type_name("SPEC");
    verify_input->type_name("SPEC");
    verify_sig->type_name("SPEC");

    verify->callback([verify, verify_bits, verify_key, verify_input, verify_sig]() {
        auto pub_buf = read_input(verify_key->as<std::string>());
        if (!pub_buf.has_value()) { die(pub_buf.error()); }
        auto msg_buf = read_input(verify_input->as<std::string>());
        if (!msg_buf.has_value()) { die(msg_buf.error()); }
        auto sig_buf = read_input(verify_sig->as<std::string>());
        if (!sig_buf.has_value()) { die(sig_buf.error()); }

        const auto run = [&]<RsaKeyBits KB>() {
            RsaPublicKey<KB> pub{.public_key_der = SecureBuffer(pub_buf->size())};
            std::copy(pub_buf->data(), pub_buf->data() + pub_buf->size(), pub.public_key_der.data());

            const auto result = rsa_pss_verify<KB>(pub, *msg_buf, *sig_buf);
            if (!result.has_value()) { die(result.error()); }
            if (!*result) {
                std::cerr << "signature invalid\n";
                std::exit(1);  // NOLINT(concurrency-mt-unsafe)
            }
        };

        const RsaKeyBits kb = parse_rsa_bits(verify_bits->as<std::string>());
        if (kb == RsaKeyBits::Bits3072) { run.template operator()<RsaKeyBits::Bits3072>(); }
        else                            { run.template operator()<RsaKeyBits::Bits4096>(); }

        (void)verify;
    });
}

}  // namespace scli
