// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <filesystem>
#include <string>

#include <gtest/gtest.h>

#include "cli_test_runner.hpp"


namespace scli_test {

class EcdhTests : public ::testing::Test {
protected:
    static auto scli() -> const std::string& {
        static const std::string path{SCLI_PATH};  // NOLINT(cppcoreguidelines-pro-bounds-array-to-pointer-decay,hicpp-no-array-decay)
        return path;
    }

    void TearDown() override {
        for (const auto& p : tmp_files_) { std::filesystem::remove(p); }
    }

    auto tmp(const std::string& name) -> std::string {
        const std::string path = (std::filesystem::temp_directory_path() / name).string();
        tmp_files_.push_back(path);
        return path;
    }

private:
    std::vector<std::string> tmp_files_;
};


// Generate a key pair to two temp files; returns {priv, pub} paths.
[[nodiscard]]
static auto ecdh_keygen(const std::string& scli_path,
                        const std::string& curve,
                        const std::string& priv_path,
                        const std::string& pub_path) -> bool
{
    const auto r = run_scli(scli_path,
        "ecdh keygen --curve " + curve +
        " --out-private " + priv_path +
        " --out-public "  + pub_path);
    return r.exit_code == 0;
}


TEST_F(EcdhTests, KeygenP256ProducesFiles) {
    const std::string priv = tmp("ecdh_kg_priv.der");
    const std::string pub  = tmp("ecdh_kg_pub.der");
    const auto r = run_scli(scli(),
        "ecdh keygen --curve p256 --out-private " + priv + " --out-public " + pub);
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_GT(std::filesystem::file_size(priv), 0U);
    EXPECT_GT(std::filesystem::file_size(pub),  0U);
}

TEST_F(EcdhTests, RoundTripP256) {
    const std::string a_priv = tmp("ecdh_a_priv_256.der");
    const std::string a_pub  = tmp("ecdh_a_pub_256.der");
    const std::string b_priv = tmp("ecdh_b_priv_256.der");
    const std::string b_pub  = tmp("ecdh_b_pub_256.der");

    ASSERT_TRUE(ecdh_keygen(scli(), "p256", a_priv, a_pub));
    ASSERT_TRUE(ecdh_keygen(scli(), "p256", b_priv, b_pub));

    const auto sa = run_scli(scli(),
        "ecdh compute --curve p256 --key " + a_priv + " --peer-public " + b_pub);
    const auto sb = run_scli(scli(),
        "ecdh compute --curve p256 --key " + b_priv + " --peer-public " + a_pub);

    ASSERT_EQ(sa.exit_code, 0);
    ASSERT_EQ(sb.exit_code, 0);
    EXPECT_FALSE(sa.stdout_text.empty());
    EXPECT_EQ(sa.stdout_text, sb.stdout_text);
}

TEST_F(EcdhTests, RoundTripP384) {
    const std::string a_priv = tmp("ecdh_a_priv_384.der");
    const std::string a_pub  = tmp("ecdh_a_pub_384.der");
    const std::string b_priv = tmp("ecdh_b_priv_384.der");
    const std::string b_pub  = tmp("ecdh_b_pub_384.der");

    ASSERT_TRUE(ecdh_keygen(scli(), "p384", a_priv, a_pub));
    ASSERT_TRUE(ecdh_keygen(scli(), "p384", b_priv, b_pub));

    const auto sa = run_scli(scli(),
        "ecdh compute --curve p384 --key " + a_priv + " --peer-public " + b_pub);
    const auto sb = run_scli(scli(),
        "ecdh compute --curve p384 --key " + b_priv + " --peer-public " + a_pub);

    ASSERT_EQ(sa.exit_code, 0);
    ASSERT_EQ(sb.exit_code, 0);
    EXPECT_EQ(sa.stdout_text, sb.stdout_text);
}

TEST_F(EcdhTests, RoundTripP521) {
    const std::string a_priv = tmp("ecdh_a_priv_521.der");
    const std::string a_pub  = tmp("ecdh_a_pub_521.der");
    const std::string b_priv = tmp("ecdh_b_priv_521.der");
    const std::string b_pub  = tmp("ecdh_b_pub_521.der");

    ASSERT_TRUE(ecdh_keygen(scli(), "p521", a_priv, a_pub));
    ASSERT_TRUE(ecdh_keygen(scli(), "p521", b_priv, b_pub));

    const auto sa = run_scli(scli(),
        "ecdh compute --curve p521 --key " + a_priv + " --peer-public " + b_pub);
    const auto sb = run_scli(scli(),
        "ecdh compute --curve p521 --key " + b_priv + " --peer-public " + a_pub);

    ASSERT_EQ(sa.exit_code, 0);
    ASSERT_EQ(sb.exit_code, 0);
    EXPECT_EQ(sa.stdout_text, sb.stdout_text);
}

TEST_F(EcdhTests, DifferentPeersProduceDifferentSecrets) {
    const std::string a_priv = tmp("ecdh_diff_a_priv.der");
    const std::string a_pub  = tmp("ecdh_diff_a_pub.der");
    const std::string b_priv = tmp("ecdh_diff_b_priv.der");
    const std::string b_pub  = tmp("ecdh_diff_b_pub.der");
    const std::string c_priv = tmp("ecdh_diff_c_priv.der");
    const std::string c_pub  = tmp("ecdh_diff_c_pub.der");

    ASSERT_TRUE(ecdh_keygen(scli(), "p256", a_priv, a_pub));
    ASSERT_TRUE(ecdh_keygen(scli(), "p256", b_priv, b_pub));
    ASSERT_TRUE(ecdh_keygen(scli(), "p256", c_priv, c_pub));

    const auto s_ab = run_scli(scli(),
        "ecdh compute --curve p256 --key " + a_priv + " --peer-public " + b_pub);
    const auto s_ac = run_scli(scli(),
        "ecdh compute --curve p256 --key " + a_priv + " --peer-public " + c_pub);

    ASSERT_EQ(s_ab.exit_code, 0);
    ASSERT_EQ(s_ac.exit_code, 0);
    EXPECT_NE(s_ab.stdout_text, s_ac.stdout_text);
}

TEST_F(EcdhTests, SharedSecretOutputToFile) {
    const std::string a_priv   = tmp("ecdh_file_a_priv.der");
    const std::string a_pub    = tmp("ecdh_file_a_pub.der");
    const std::string b_priv   = tmp("ecdh_file_b_priv.der");
    const std::string b_pub    = tmp("ecdh_file_b_pub.der");
    const std::string secret_a = tmp("ecdh_secret_a.bin");
    const std::string secret_b = tmp("ecdh_secret_b.bin");

    ASSERT_TRUE(ecdh_keygen(scli(), "p256", a_priv, a_pub));
    ASSERT_TRUE(ecdh_keygen(scli(), "p256", b_priv, b_pub));

    const auto ra = run_scli(scli(),
        "ecdh compute --curve p256 --key " + a_priv +
        " --peer-public " + b_pub + " --output " + secret_a);
    const auto rb = run_scli(scli(),
        "ecdh compute --curve p256 --key " + b_priv +
        " --peer-public " + a_pub + " --output " + secret_b);

    ASSERT_EQ(ra.exit_code, 0);
    ASSERT_EQ(rb.exit_code, 0);

    // P-256 shared secret is 32 raw bytes.
    EXPECT_EQ(std::filesystem::file_size(secret_a), 32U);
    EXPECT_EQ(read_file_bytes(secret_a), read_file_bytes(secret_b));
}

TEST_F(EcdhTests, MixedIO_PrivateKeyB64_PeerPublicFromFile) {
    // keygen for party A to files; export A's private key as base64 via stdout,
    // then compute with --key base64:<...> and --peer-public from file.
    const std::string a_priv = tmp("ecdh_mix_a_priv.der");
    const std::string a_pub  = tmp("ecdh_mix_a_pub.der");
    const std::string b_priv = tmp("ecdh_mix_b_priv.der");
    const std::string b_pub  = tmp("ecdh_mix_b_pub.der");

    ASSERT_TRUE(ecdh_keygen(scli(), "p256", a_priv, a_pub));
    ASSERT_TRUE(ecdh_keygen(scli(), "p256", b_priv, b_pub));

    // Get A's private key as base64 (via stdout, no --out-private flag).
    const auto a_priv_b64_r = run_scli(scli(),
        "ecdh keygen --curve p256 --out-public " + tmp("ecdh_mix_a2_pub.der"));
    // That keygen generates a new key; instead read from the file we made.
    const auto a_priv_bytes = read_file_bytes(a_priv);
    // base64-encode manually using the helper.
    std::string a_priv_b64;
    {
        static constexpr const char* kAlpha =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        uint32_t acc = 0;
        int bits = 0;
        for (const uint8_t byte : a_priv_bytes) {
            acc  = (acc << 8U) | byte;
            bits += 8;
            while (bits >= 6) {
                bits -= 6;
                a_priv_b64 += kAlpha[(acc >> static_cast<unsigned>(bits)) & 0x3FU];
            }
        }
        if (bits > 0) {
            a_priv_b64 += kAlpha[(acc << static_cast<unsigned>(6 - bits)) & 0x3FU];
        }
        while (a_priv_b64.size() % 4 != 0) { a_priv_b64 += '='; }
    }

    const auto sa = run_scli(scli(),
        "ecdh compute --curve p256"
        " --key base64:" + a_priv_b64 +
        " --peer-public " + b_pub);
    const auto sb = run_scli(scli(),
        "ecdh compute --curve p256 --key " + b_priv + " --peer-public " + a_pub);

    ASSERT_EQ(sa.exit_code, 0);
    ASSERT_EQ(sb.exit_code, 0);
    EXPECT_EQ(sa.stdout_text, sb.stdout_text);
}

TEST_F(EcdhTests, UnknownCurveExitsNonZero) {
    const auto r = run_scli(scli(), "ecdh keygen --curve secp256k1");
    EXPECT_NE(r.exit_code, 0);
}

TEST_F(EcdhTests, ComputeWithWrongCurveExitsNonZero) {
    // Generate P-256 keys but try to compute with P-384.
    const std::string priv = tmp("ecdh_wrong_priv.der");
    const std::string pub  = tmp("ecdh_wrong_pub.der");
    ASSERT_TRUE(ecdh_keygen(scli(), "p256", priv, pub));

    const auto r = run_scli(scli(),
        "ecdh compute --curve p384 --key " + priv + " --peer-public " + pub);
    EXPECT_NE(r.exit_code, 0);
}

}  // namespace scli_test
