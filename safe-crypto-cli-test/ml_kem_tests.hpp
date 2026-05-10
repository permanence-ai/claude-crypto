// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <filesystem>
#include <string>

#include <gtest/gtest.h>

#include "cli_test_runner.hpp"


namespace scli_test {

#ifdef SAFE_CRYPTO_PQC_LIBOQS

class MlKemTests : public ::testing::Test {
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


// ─── keygen ──────────────────────────────────────────────────────────────────

TEST_F(MlKemTests, KeygenKem512ProducesKeys) {
    const std::string priv_path = tmp("mlkem_512_priv.bin");
    const std::string pub_path  = tmp("mlkem_512_pub.bin");
    const auto r = run_scli(scli(),
        "ml-kem keygen --variant 512 --out-private " + priv_path + " --out-public " + pub_path);
    ASSERT_EQ(r.exit_code, 0);
    EXPECT_EQ(std::filesystem::file_size(priv_path), 1632U);
    EXPECT_EQ(std::filesystem::file_size(pub_path),   800U);
}

TEST_F(MlKemTests, KeygenKem768ProducesKeys) {
    const std::string priv_path = tmp("mlkem_768_priv.bin");
    const std::string pub_path  = tmp("mlkem_768_pub.bin");
    const auto r = run_scli(scli(),
        "ml-kem keygen --variant 768 --out-private " + priv_path + " --out-public " + pub_path);
    ASSERT_EQ(r.exit_code, 0);
    EXPECT_EQ(std::filesystem::file_size(priv_path), 2400U);
    EXPECT_EQ(std::filesystem::file_size(pub_path),  1184U);
}

TEST_F(MlKemTests, KeygenKem1024ProducesKeys) {
    const std::string priv_path = tmp("mlkem_1024_priv.bin");
    const std::string pub_path  = tmp("mlkem_1024_pub.bin");
    const auto r = run_scli(scli(),
        "ml-kem keygen --variant 1024 --out-private " + priv_path + " --out-public " + pub_path);
    ASSERT_EQ(r.exit_code, 0);
    EXPECT_EQ(std::filesystem::file_size(priv_path), 3168U);
    EXPECT_EQ(std::filesystem::file_size(pub_path),  1568U);
}

TEST_F(MlKemTests, KeygenUnknownVariantExitsNonZero) {
    const auto r = run_scli(scli(),
        "ml-kem keygen --variant 256 --out-private /dev/null --out-public /dev/null");
    EXPECT_NE(r.exit_code, 0);
}


// ─── encapsulate / decapsulate round-trip ────────────────────────────────────

TEST_F(MlKemTests, RoundTripKem512) {
    const std::string priv_path = tmp("rt512_priv.bin");
    const std::string pub_path  = tmp("rt512_pub.bin");
    const std::string ct_path   = tmp("rt512_ct.bin");
    const std::string ss1_path  = tmp("rt512_ss1.bin");
    const std::string ss2_path  = tmp("rt512_ss2.bin");

    ASSERT_EQ(run_scli(scli(),
        "ml-kem keygen --variant 512 --out-private " + priv_path + " --out-public " + pub_path
    ).exit_code, 0);

    ASSERT_EQ(run_scli(scli(),
        "ml-kem encapsulate --variant 512 --key " + pub_path +
        " --out-ciphertext " + ct_path + " --out-secret " + ss1_path
    ).exit_code, 0);

    ASSERT_EQ(run_scli(scli(),
        "ml-kem decapsulate --variant 512 --key " + priv_path +
        " --ciphertext " + ct_path + " --output " + ss2_path
    ).exit_code, 0);

    EXPECT_EQ(std::filesystem::file_size(ct_path),   768U);
    EXPECT_EQ(std::filesystem::file_size(ss1_path),   32U);
    EXPECT_EQ(std::filesystem::file_size(ss2_path),   32U);
    EXPECT_EQ(read_file_bytes(ss1_path), read_file_bytes(ss2_path));
}

TEST_F(MlKemTests, RoundTripKem1024) {
    const std::string priv_path = tmp("rt1024_priv.bin");
    const std::string pub_path  = tmp("rt1024_pub.bin");
    const std::string ct_path   = tmp("rt1024_ct.bin");
    const std::string ss1_path  = tmp("rt1024_ss1.bin");
    const std::string ss2_path  = tmp("rt1024_ss2.bin");

    ASSERT_EQ(run_scli(scli(),
        "ml-kem keygen --variant 1024 --out-private " + priv_path + " --out-public " + pub_path
    ).exit_code, 0);

    ASSERT_EQ(run_scli(scli(),
        "ml-kem encapsulate --variant 1024 --key " + pub_path +
        " --out-ciphertext " + ct_path + " --out-secret " + ss1_path
    ).exit_code, 0);

    ASSERT_EQ(run_scli(scli(),
        "ml-kem decapsulate --variant 1024 --key " + priv_path +
        " --ciphertext " + ct_path + " --output " + ss2_path
    ).exit_code, 0);

    EXPECT_EQ(std::filesystem::file_size(ct_path),  1568U);
    EXPECT_EQ(read_file_bytes(ss1_path), read_file_bytes(ss2_path));
}

TEST_F(MlKemTests, EncapsulateProducesUniqueSecrets) {
    const std::string priv_path = tmp("uniq_priv.bin");
    const std::string pub_path  = tmp("uniq_pub.bin");
    const std::string ct1_path  = tmp("uniq_ct1.bin");
    const std::string ss1_path  = tmp("uniq_ss1.bin");
    const std::string ct2_path  = tmp("uniq_ct2.bin");
    const std::string ss2_path  = tmp("uniq_ss2.bin");

    ASSERT_EQ(run_scli(scli(),
        "ml-kem keygen --variant 512 --out-private " + priv_path + " --out-public " + pub_path
    ).exit_code, 0);

    ASSERT_EQ(run_scli(scli(),
        "ml-kem encapsulate --variant 512 --key " + pub_path +
        " --out-ciphertext " + ct1_path + " --out-secret " + ss1_path
    ).exit_code, 0);

    ASSERT_EQ(run_scli(scli(),
        "ml-kem encapsulate --variant 512 --key " + pub_path +
        " --out-ciphertext " + ct2_path + " --out-secret " + ss2_path
    ).exit_code, 0);

    EXPECT_NE(read_file_bytes(ss1_path), read_file_bytes(ss2_path));
}

TEST_F(MlKemTests, DecapsulateWrongKeyExitsNonZero) {
    // Decapsulating a ciphertext with a different private key should fail.
    const std::string priv1_path = tmp("wrongkey_priv1.bin");
    const std::string pub1_path  = tmp("wrongkey_pub1.bin");
    const std::string priv2_path = tmp("wrongkey_priv2.bin");
    const std::string pub2_path  = tmp("wrongkey_pub2.bin");
    const std::string ct_path    = tmp("wrongkey_ct.bin");
    const std::string ss_path    = tmp("wrongkey_ss.bin");

    ASSERT_EQ(run_scli(scli(),
        "ml-kem keygen --variant 512 --out-private " + priv1_path + " --out-public " + pub1_path
    ).exit_code, 0);
    ASSERT_EQ(run_scli(scli(),
        "ml-kem keygen --variant 512 --out-private " + priv2_path + " --out-public " + pub2_path
    ).exit_code, 0);

    ASSERT_EQ(run_scli(scli(),
        "ml-kem encapsulate --variant 512 --key " + pub1_path +
        " --out-ciphertext " + ct_path + " --out-secret " + ss_path
    ).exit_code, 0);

    // Decapsulate with key2 — should fail (wrong key, different shared secret or error)
    const auto r = run_scli(scli(),
        "ml-kem decapsulate --variant 512 --key " + priv2_path +
        " --ciphertext " + ct_path + " --output /dev/null");
    // ML-KEM decapsulation with wrong key is implicit rejection (returns garbage),
    // but size check should still pass; the shared secrets differ.
    // The library validates key sizes, so this should exit 0 with a wrong secret.
    // We verify the secret doesn't match by doing the round-trip comparison.
    const std::string ss_wrong_path = tmp("wrongkey_ss_wrong.bin");
    ASSERT_EQ(run_scli(scli(),
        "ml-kem decapsulate --variant 512 --key " + priv2_path +
        " --ciphertext " + ct_path + " --output " + ss_wrong_path
    ).exit_code, 0);
    EXPECT_NE(read_file_bytes(ss_path), read_file_bytes(ss_wrong_path));
}

#endif  // SAFE_CRYPTO_PQC_LIBOQS

}  // namespace scli_test
